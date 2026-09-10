# Publish CyberIntel Copilot to GitHub

The local repository is already initialized and has a clean first commit on the `main` branch. The generated RAG database, PDFs, NVD cache, virtual environment, and environment file are excluded by `.gitignore`.

## Create the GitHub repository in your browser

1. Sign in at [GitHub](https://github.com/).
2. Click the **+** button in the upper-right corner, then choose **New repository**.
3. Set the repository name to `cyberintel-copilot`.
4. Choose **Public** for a portfolio project, unless the code or screenshots contain work you cannot share.
5. Do **not** tick “Add a README”, “Add .gitignore”, or “Choose a license”. They already exist locally.
6. Click **Create repository**.
7. Copy the HTTPS URL shown by GitHub. It will look like `https://github.com/YOUR-USERNAME/cyberintel-copilot.git`.

## Connect and push from PowerShell

Run these commands in the project folder. Replace `YOUR-USERNAME` with your real GitHub username.

```powershell
cd C:\Users\sanyaagr\Documents\ChatGPT\GL\cyberintel-copilot
git remote add origin https://github.com/YOUR-USERNAME/cyberintel-copilot.git
git push -u origin main
```

GitHub may open a browser window to let you sign in. This is normal. Do not paste a password into PowerShell. GitHub uses browser-based authentication or a personal access token when needed.

## Verify it worked

```powershell
git remote -v
git status
```

Then refresh the GitHub repository page. You should see `README.md` rendered on the front page and the architecture diagrams rendered by GitHub.

## Publish later changes

After you make and test a change:

```powershell
git status
git add .
git commit -m "Describe the change here"
git push
```

Before `git add .`, check that no real threat report, sensitive screenshot, API key, `.env` file, or generated local data is listed in `git status`.
