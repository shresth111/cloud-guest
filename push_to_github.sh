#!/bin/bash
set -e

if [ -z "$GITHUB_TOKEN" ]; then
  echo "Error: GITHUB_TOKEN environment variable is not set."
  echo "Please provide your GitHub Personal Access Token (PAT) via the Settings menu in AI Studio."
  exit 1
fi

echo "Setting remote URL with GITHUB_TOKEN..."
git remote set-url origin "https://${GITHUB_TOKEN}@github.com/shresth111/cloud-guest.git"

echo "Pushing code to GitHub repository..."
git push -u origin main --force

echo "Successfully pushed to GitHub!"
