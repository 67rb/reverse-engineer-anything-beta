# Reverse Engineer Anything — Local Analyzer

> **BETA — experimental local tool.** This is a Mac-specific browser wrapper for selected REA workflows, not a hosted website or a complete interface to every REA command.

The app provides a local web UI for running REA's JavaScript/Electron analysis workflow, capturing a public website's first page, and optionally asking ChatGPT to explain displayed REA findings. It wraps the installed `rea` command; it does not include or replace the upstream REA project.

## What is in this beta

- Select a macOS app bundle, `app.asar`, extracted JavaScript/Electron app folder, or public HTTP(S) website.
- Run the bounded analysis flow and review or copy the returned evidence.
- Optionally sign in to ChatGPT and request an explanation grounded in the displayed analysis.
- Bind the local server to loopback (`127.0.0.1`), with a local proxy that resolves and pins public IPv4 destinations and rejects private or local network addresses for website capture.

## Beta limits and data handling

- Requires macOS, Node.js, the `rea` command, and Chrome, Chromium, Brave, or Edge for website capture.
- Website analysis covers the first public page and does not replay sign-in, later pages, or page interactions. Captured scripts are bounded and analyzed locally.
- The selected application files are analyzed on this Mac and are not uploaded by the app. If you request a ChatGPT explanation, your question and displayed REA output (up to 80,000 characters) are sent to OpenAI; website results can contain page text, code, or URLs.
- ChatGPT credentials are stored outside this repository in the user's local Application Support directory. Do not commit credentials or local analysis captures.
- The tool listens only on `127.0.0.1`; it is not configured for public or remote deployment.

## Start locally

Double-click **Start REA Website.command**. Keep the Terminal window open while using the app, then press Ctrl+C to stop it. Or run from the project directory:

```sh
node server.mjs --open
```
