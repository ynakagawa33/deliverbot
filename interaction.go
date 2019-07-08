package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"github.com/blang/semver"
	"github.com/nlopes/slack"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type interactionHandler struct {
	slackClient       *slack.Client
	verificationToken string
	configurationDirectoryPath string
	configurationFileExtension string
	environments      []string
}

func (h interactionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sugar.Errorf("Invalid method: %s", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sugar.Errorf("Failed to read request body: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jsonStr, err := url.QueryUnescape(string(buf)[8:])
	if err != nil {
		sugar.Errorf("Failed to un-escape request body: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var message slack.AttachmentActionCallback
	if err := json.Unmarshal([]byte(jsonStr), &message); err != nil {
		sugar.Errorf("Failed to decode json message from slack: %s", jsonStr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if message.Token != h.verificationToken {
		sugar.Errorf("Invalid token: %s", message.Token)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	action := message.Actions[0]
	parameters := NewBuildParameters(action.Value)
	if action.Value == "" {
		parameters = NewBuildParameters(action.SelectedOptions[0].Value)
	}
	switch action.Name {
	case actionBranch:
		// FIXME
		var currentVersion string
		var currentBuildNumber string
		var nextPatch string
		var nextMinor string
		var nextMajor string
		var nextBuildNumber string

		file, err := service.File(parameters.Branch, service.XcconfigPath)
		if err != nil {
			responseError(w, message.OriginalMessage, "Error occurred.", fmt.Sprintf("%s", err))
			return
		}

		versions := map[string]string{}

		lines := strings.Split(string(file), "\n")
		for _, line := range lines {
			if !strings.Contains(line, "=") {
				continue
			}
			pair := strings.Split(line, "=")
			versions[strings.TrimSpace(pair[0])] = strings.TrimSpace(pair[1])
		}

		currentVersion = versions["APP_VERSION"]
		currentBuildNumber = versions["BUILD_VERSION"]

		version, err := semver.Make(currentVersion)
		if err != nil {
			responseError(w, message.OriginalMessage, "Error occurred.", fmt.Sprintf("%s", err))
			return
		}
		version.Patch += 1
		nextPatch = version.String()

		version.Minor += 1
		version.Patch = 0
		nextMinor = version.String()

		version.Major += 1
		version.Minor = 0
		version.Patch = 0
		nextMajor = version.String()

		buildNumber, err := strconv.Atoi(currentBuildNumber)
		if err != nil {
			responseError(w, message.OriginalMessage, "Error occurred.", fmt.Sprintf("%s", err))
			return
		}
		nextBuildNumber = strconv.Itoa(buildNumber + 1)

		buildParameters := BuildParameters{
			Branch:             parameters.Branch,
			Version:            "",
			BuildNumber:        "",
			CurrentVersion:     currentVersion,
			CurrentBuildNumber: currentBuildNumber,
			NextPatch:          nextPatch,
			NextMinor:          nextMinor,
			NextMajor:          nextMajor,
			NextBuildNumber:    nextBuildNumber,
		}

		responseAction(w, message.OriginalMessage, fmt.Sprintf("Branch: `%s` ✔︎\nCurrent Version: `%s (%s)`\nNext Version:", parameters.Branch, currentVersion, currentBuildNumber), versionOptions(buildParameters))
	case actionVersion:
		currentVersion := fmt.Sprintf("%s (%s)", parameters.CurrentVersion, parameters.CurrentBuildNumber)
		responseAction(w, message.OriginalMessage, fmt.Sprintf("Branch: `%s` ✔︎\nCurrent Version: `%s`\nNext Version: `%s` ✔︎\nBuild:", parameters.Branch, currentVersion, parameters.Version), buildNumberOptions(parameters))
	case actionBuildNumber:
		currentVersion := fmt.Sprintf("%s (%s)", parameters.CurrentVersion, parameters.CurrentBuildNumber)
		nextVersion := fmt.Sprintf("%s (%s)", parameters.Version, parameters.BuildNumber)
		responseAction(w, message.OriginalMessage, fmt.Sprintf("Branch: `%s` ✔︎\nCurrent Version: `%s`\nNext Version: `%s` ✔︎", parameters.Branch, currentVersion, nextVersion), runOptions(parameters))
	case actionRelease, actionInternal:
		// FIXME

		nextVersion := fmt.Sprintf("%s (%s)", parameters.Version, parameters.BuildNumber)
		responseMessage(w, message.OriginalMessage, fmt.Sprintf("Releasing `%s` to %s ...", nextVersion, destination(action.Name)), "")

		go func() {
			fileChanges := []FileChange{}
			appVersionRegex := regexp.MustCompile(`^(APP_VERSION\s*=\s*)(([0-9]\.*)+)$`)
			buildVersionRegex := regexp.MustCompile(`^(BUILD_VERSION\s*=\s*)([0-9]+)$`)
			for _, environment := range h.environments {
				path := h.configurationDirectoryPath + environment + h.configurationFileExtension
				if err != nil {
					responseError(w, message.OriginalMessage, "Error occurred.", fmt.Sprintf("%s", err))
					break
				}
				file, err := service.File(parameters.Branch, path)
				if err != nil {
					responseError(w, message.OriginalMessage, "Error occurred.", fmt.Sprintf("%s", err))
					return
				}
				rawFileContents := ""
				lines := strings.Split(string(file), "\n")
				for _, line := range lines {
					appVersionMatch := appVersionRegex.FindAllStringSubmatch(line, -1)
					if len(appVersionMatch) != 0 {
						line = appVersionMatch[0][1] + parameters.Version
					}
					buildVersionMatch := buildVersionRegex.FindAllStringSubmatch(line, -1)
					if len(buildVersionMatch) != 0 {
						line = buildVersionMatch[0][1] + parameters.BuildNumber
					}
					rawFileContents = rawFileContents + line + "\n"
				}
				bytes := []byte(rawFileContents)
				fileChanges = append(fileChanges, FileChange {
					Content: bytes,
					Path:    path,
				})
			}
			if len(fileChanges) != len(h.environments) {
				responseError(w, message.OriginalMessage, "Precondition failed. This is because fileChanges length not equal h.environments length.", fmt.Sprintf("len(fileChanges):%d len(h.environments):%d", len(fileChanges), len(h.environments)))
				return
			}

			timestamp := strconv.FormatInt(time.Now().Unix(), 10)
			commitBranch := fmt.Sprintf("%s/%s-%s-%s", branchPrefix(action.Name), parameters.Version, parameters.BuildNumber, timestamp)
			title := fmt.Sprintf("Release %s (%s)", parameters.Version, parameters.BuildNumber)

			changelog := generateChangeLog(service, parameters.Version, parameters.Branch)

			commitMessage := fmt.Sprintf("%s", changelog)

			u, err := service.PushPullRequest(PullRequest{
				TargetBranch:  parameters.Branch,
				CommitBranch:  commitBranch,
				FileChanges:   fileChanges,
				Title:         title,
				CommitMessage: commitMessage,
			})
			if err != nil {
				e := fmt.Errorf("failed to create pull request %s", err)
				sugar.Error(e)
				h.slackClient.PostMessage(message.Channel.ID, fmt.Sprintf("%s", e), slack.PostMessageParameters{})
			} else {
				m := fmt.Sprintf("Releasing `%s (%s)`", parameters.Version, parameters.BuildNumber)
				sugar.Infof(m)
				h.slackClient.PostMessage(message.Channel.ID, fmt.Sprintf("%s\n%s", m, *u), slack.PostMessageParameters{})
			}
		}()
	case actionCancel:
		responseMessage(w, message.OriginalMessage, fmt.Sprintf("Operation canceled by '%s'.", message.User.Name), "")
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func responseMessage(w http.ResponseWriter, original slack.Message, title, value string) {
	original.Attachments[0].Actions = []slack.AttachmentAction{}
	original.Attachments[0].Fields = []slack.AttachmentField{
		{
			Title: title,
			Value: value,
			Short: false,
		},
	}

	w.Header().Add("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&original)
}

func responseAction(w http.ResponseWriter, original slack.Message, text string, actions []slack.AttachmentAction) {
	original.Attachments[0].Text = text
	original.Attachments[0].Actions = actions

	w.Header().Add("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&original)
}

func responseError(w http.ResponseWriter, original slack.Message, title, value string) {
	original.Attachments[0].Actions = []slack.AttachmentAction{}
	original.Attachments[0].Fields = []slack.AttachmentField{
		{
			Title: title,
			Value: value,
			Short: false,
		},
	}

	w.Header().Add("Content-type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(&original)
}

func versionOptions(parameters BuildParameters) []slack.AttachmentAction {
	parameters.Version = parameters.CurrentVersion
	currentVersionAction := slack.AttachmentAction{
		Name:  actionVersion,
		Text:  parameters.Version,
		Value: parameters.string(),
		Type:  "button",
		Style: "primary",
	}

	parameters.Version = parameters.NextPatch
	patchVersionAction := slack.AttachmentAction{
		Name:  actionVersion,
		Text:  parameters.Version,
		Value: parameters.string(),
		Type:  "button",
	}

	parameters.Version = parameters.NextMinor
	minorVersionAction := slack.AttachmentAction{
		Name:  actionVersion,
		Text:  parameters.Version,
		Value: parameters.string(),
		Type:  "button",
	}

	parameters.Version = parameters.NextMajor
	majorVersionAction := slack.AttachmentAction{
		Name:  actionVersion,
		Text:  parameters.Version,
		Value: parameters.string(),
		Type:  "button",
	}
	actions := []slack.AttachmentAction{
		currentVersionAction,
		patchVersionAction,
		minorVersionAction,
		majorVersionAction,
		cancelAction(),
	}
	return actions
}

func buildNumberOptions(parameters BuildParameters) []slack.AttachmentAction {
	parameters.BuildNumber = parameters.NextBuildNumber
	currentBuildNumberAction := slack.AttachmentAction{
		Name:  actionBuildNumber,
		Text:  parameters.BuildNumber,
		Value: parameters.string(),
		Type:  "button",
		Style: "primary",
	}

	nextBuildNumber := parameters.NextBuildNumber
	number, _ := strconv.Atoi(nextBuildNumber)
	var options []slack.AttachmentActionOption
	for i := 1; i <= number+5; i++ {
		buildNumber := strconv.Itoa(i)
		parameters.BuildNumber = buildNumber
		options = append(options, slack.AttachmentActionOption{
			Text:  buildNumber,
			Value: parameters.string(),
		})
	}
	actions := []slack.AttachmentAction{
		currentBuildNumberAction,
		{
			Name:    actionBuildNumber,
			Text:    "Build number",
			Type:    "select",
			Options: options,
		},
		cancelAction(),
	}
	return actions
}

func runOptions(parameters BuildParameters) []slack.AttachmentAction {
	releaseAction := slack.AttachmentAction{
		Name:  actionRelease,
		Text:  " TestFlight",
		Value: parameters.string(),
		Type:  "button",
		Style: "primary",
	}
	internalAction := slack.AttachmentAction{
		Name:  actionInternal,
		Text:  "⚙ Beta",
		Value: parameters.string(),
		Type:  "button",
	}
	actions := []slack.AttachmentAction{
		releaseAction,
		internalAction,
		cancelAction(),
	}
	return actions
}

func cancelAction() slack.AttachmentAction {
	return slack.AttachmentAction{
		Name:  actionCancel,
		Text:  "Cancel",
		Value: "cancel",
		Type:  "button",
		Style: "danger",
	}
}

func branchPrefix(actionName string) string {
	switch actionName {
	case actionRelease:
		return "_release"
	case actionInternal:
		return "_beta"
	}
	return "null"
}

func destination(actionName string) string {
	switch actionName {
	case actionRelease:
		return "TestFlight"
	case actionInternal:
		return "Beta"
	}
	return "Unknown"
}

func generateChangeLog(service *GitHubService, nextVersion string, branch string) string {
	latestTag, err := service.LatestTag()
	if err != nil {
		return ""
	}
	commits, err := service.Commits(*latestTag.Name, branch)
	if err != nil {
		return ""
	}

	changelog := []string{}
	for _, commit := range commits {
		var message = *commit.Commit.Message
		if *commit.Commit.Committer.Name == "GitHub" && strings.HasPrefix(message, "Merge pull request") {
			message = ":twisted_rightwards_arrows: " + strings.Join(strings.Fields(message)[:4], " ")
		}

		var log = fmt.Sprintf("* %s [%s](%s)", strings.Split(message, "\n")[0], (*commit.SHA)[:7], *commit.HTMLURL)
		user, err := service.User(*commit.Commit.Author.Name)
		if err == nil {
			log = log + fmt.Sprintf("([%s](%s))", *user.Login, *user.HTMLURL)
		}
		changelog = append([]string{log}, changelog...)
	}

	section := fmt.Sprintf("## [%s](https://github.com/%s/%s/compare/%s...%s) (%s)", nextVersion, service.Repository.Owner, service.Repository.Name, *latestTag.Name, branch, time.Now().Format("2006-01-02"))
	changelog = append([]string{section}, changelog...)

	return strings.Join(changelog, "\n")
}
