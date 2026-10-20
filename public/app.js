const form = document.querySelector("#analysis-form");
const websiteForm = document.querySelector("#website-form");
const pathInput = document.querySelector("#target-path");
const websiteUrlInput = document.querySelector("#website-url");
const chooseButton = document.querySelector("#choose-target");
const analyzeButton = document.querySelector("#analyze-button");
const websiteAnalyzeButton = document.querySelector("#website-analyze-button");
const localTargetTab = document.querySelector("#local-target-tab");
const websiteTargetTab = document.querySelector("#website-target-tab");
const localTargetPanel = document.querySelector("#local-target-panel");
const websiteTargetPanel = document.querySelector("#website-target-panel");
const statusMessage = document.querySelector("#status-message");
const connectionLabel = document.querySelector("#connection-label");
const localIndicator = document.querySelector(".local-indicator");
const emptyState = document.querySelector("#empty-state");
const websitePreview = document.querySelector("#website-preview");
const websitePreviewImage = document.querySelector("#website-preview-image");
const resultOutput = document.querySelector("#result-output");
const resultTitle = document.querySelector("#result-title");
const resultState = document.querySelector("#result-state");
const copyButton = document.querySelector("#copy-output");
const chatgptLabel = document.querySelector("#chatgpt-label");
const chatgptSignInButton = document.querySelector("#chatgpt-signin");
const chatgptSignInLabel = document.querySelector("#chatgpt-signin-label");
const chatgptAddAccountButton = document.querySelector("#chatgpt-add-account");
const chatgptSignOutButton = document.querySelector("#chatgpt-signout");
const chatgptAccountSelect = document.querySelector("#chatgpt-account");
const manageUsageLink = document.querySelector("#manage-usage");
const aiPanel = document.querySelector("#ai-panel");
const aiModelSelect = document.querySelector("#ai-model");
const chatgptPrompt = document.querySelector("#chatgpt-prompt");
const explainButton = document.querySelector("#explain-button");
const aiStatus = document.querySelector("#ai-status");
const aiOutput = document.querySelector("#ai-output");
const welcomeDialog = document.querySelector("#chatgpt-welcome");
const welcomeDismiss = document.querySelector("#welcome-dismiss");
const fileOpenNotice = document.querySelector("#file-open-notice");

const CHATGPT_MODEL = "gpt-6-luna";

let authState = null;
let latestAnalysisOutput = "";
let latestDisplayOutput = "";
let latestAnalysisTargetKind = "application";
let modelCatalogReady = false;
let authPollTimer = null;
let authPollBusy = false;

function setStatus(message, kind) {
  statusMessage.textContent = message;
  statusMessage.className = "status-message" + (kind ? " " + kind : "");
}

function setResultState(label, kind) {
  resultState.textContent = label;
  resultState.className = "result-state" + (kind ? " " + kind : "");
}

function renderAnalysisOutput(output, overview = null) {
  resultOutput.replaceChildren();
  if (overview) {
    const section = document.createElement("section");
    section.className = "result-overview";
    section.setAttribute("aria-label", "Website analysis summary");

    const heading = document.createElement("div");
    heading.className = "overview-heading";
    const title = document.createElement("h3");
    title.textContent = "What REA captured";
    const page = document.createElement("p");
    page.textContent = overview.loadedUrl || overview.requestedUrl || "Public website";
    heading.append(title, page);
    section.append(heading);

    const stats = overview.javascript?.statistics || {};
    const graph = overview.javascript?.graph;
    const semantic = overview.javascript?.semanticGraph;
    const count = (value) => Number.isFinite(Number(value)) ? Number(value).toLocaleString() : "—";
    const metrics = [
      ["Page requests", count(overview.networkRequests)],
      ["Scripts exported", count(overview.exportedScripts) + " / " + count(overview.observedScripts)],
      ["JS files parsed", count(stats.parsed_javascript_files)],
      ["Static findings", count(stats.findings)],
      [graph?.sampled ? "Application graph sample" : "Application graph", graph ? count(graph.nodes) + " nodes · " + count(graph.edges) + " links" + (graph.sampled ? " shown" : "") : "No script bytes"],
      [semantic?.sampled ? "Semantic sample" : "Semantic relations", semantic ? count(semantic.relations) + " relations · " + count(semantic.unknowns) + " unknowns" + (semantic.sampled ? " shown" : "") : "Not available"],
    ];
    const grid = document.createElement("div");
    grid.className = "overview-grid";
    for (const [label, value] of metrics) {
      const card = document.createElement("div");
      card.className = "overview-card";
      const metricLabel = document.createElement("span");
      metricLabel.className = "overview-metric-label";
      metricLabel.textContent = label;
      const metricValue = document.createElement("strong");
      metricValue.textContent = value;
      card.append(metricLabel, metricValue);
      grid.append(card);
    }
    section.append(grid);

    const capture = document.createElement("p");
    capture.className = "overview-note";
    const duration = overview.durationMs === null ? "" : " Page load capture took " + (Number(overview.durationMs) / 1000).toFixed(1) + " seconds.";
    const access = overview.accessibilityCaptured ? " The page structure and accessibility tree were captured." : "";
    const sampleLimit = Number(overview.sampleLimit) || 50;
    const sampleNote = graph?.sampled || semantic?.sampled
      ? " The evidence lists show up to the first " + sampleLimit + " records; REA's coverage fields report known analysis limits."
      : "";
    capture.textContent = "This covers JavaScript retained from the initial public page. It does not cover signed-in pages, later interactions, or server-side code." + sampleNote + duration + access;
    section.append(capture);
    resultOutput.append(section);

    const details = document.createElement("details");
    details.className = "evidence-details";
    const summary = document.createElement("summary");
    summary.textContent = "Show sampled REA evidence and captured page text";
    const evidence = document.createElement("pre");
    evidence.className = "evidence-pre";
    evidence.textContent = output;
    details.append(summary, evidence);
    resultOutput.append(details);
    return;
  }

  const evidence = document.createElement("pre");
  evidence.className = "evidence-pre";
  evidence.textContent = output;
  resultOutput.append(evidence);
}

function switchTargetMode(mode) {
  const website = mode === "website";
  localTargetTab.classList.toggle("active", !website);
  websiteTargetTab.classList.toggle("active", website);
  localTargetTab.setAttribute("aria-selected", String(!website));
  websiteTargetTab.setAttribute("aria-selected", String(website));
  localTargetPanel.hidden = website;
  websiteTargetPanel.hidden = !website;
  (website ? websiteUrlInput : pathInput).focus();
}

localTargetTab.addEventListener("click", () => switchTargetMode("application"));
websiteTargetTab.addEventListener("click", () => switchTargetMode("website"));

async function readResponse(response) {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return { error: text || "The local server returned an unreadable response." };
  }
}

function setAiStatus(message, kind) {
  aiStatus.textContent = message;
  aiStatus.className = "ai-status" + (kind ? " " + kind : "");
}

function setAiStatusWithUsageLink(message, kind) {
  aiStatus.replaceChildren();
  aiStatus.append(document.createTextNode(message + " "));
  const link = document.createElement("a");
  link.href = "https://chatgpt.com/settings/usage";
  link.target = "_blank";
  link.rel = "noreferrer";
  link.textContent = "Manage usage";
  aiStatus.append(link);
  aiStatus.className = "ai-status" + (kind ? " " + kind : "");
}

function maybeShowWelcome() {
  let alreadySeen = false;
  try { alreadySeen = localStorage.getItem("reaChatGPTPlanWelcomeSeen") === "yes"; } catch { /* Keep the sign-in usable when storage is disabled. */ }
  if (authState?.connected && !alreadySeen && !welcomeDialog.open) welcomeDialog.showModal();
}

function renderChatGPTStatus(state) {
  authState = state;
  const activeAccount = (state.accounts || []).find((account) => account.clientId === state.activeClientId);
  const hasRegistration = Boolean(state.activeClientId);
  const connected = Boolean(state.connected && state.planEnabled);

  if (connected) {
    chatgptLabel.textContent = state.email ? "Using ChatGPT plan · " + state.email : "Using ChatGPT plan";
    chatgptLabel.title = state.email || "Using ChatGPT plan";
    chatgptSignInButton.hidden = true;
    chatgptSignInButton.disabled = false;
    chatgptSignInLabel.textContent = "Continue with ChatGPT";
    chatgptAddAccountButton.hidden = false;
    chatgptSignOutButton.hidden = false;
    manageUsageLink.hidden = false;
    setAiStatusWithUsageLink("Using ChatGPT plan for eligible requests.", "success");
    maybeShowWelcome();
  } else if (state.planEnabled) {
    chatgptLabel.textContent = "ChatGPT sign-in needs renewal";
    chatgptLabel.title = chatgptLabel.textContent;
    chatgptSignInButton.hidden = false;
    chatgptSignInLabel.textContent = "Continue with ChatGPT";
    chatgptAddAccountButton.hidden = false;
    chatgptSignOutButton.hidden = !state.signedIn;
    manageUsageLink.hidden = false;
    setAiStatus("Your ChatGPT sign-in needs renewal. Continue with ChatGPT to restore plan access.", "error");
  } else if (hasRegistration && state.signedIn) {
    chatgptLabel.textContent = "ChatGPT plan permission needed";
    chatgptLabel.title = chatgptLabel.textContent;
    chatgptSignInButton.hidden = false;
    chatgptSignInLabel.textContent = "Continue with ChatGPT";
    chatgptAddAccountButton.hidden = false;
    chatgptSignOutButton.hidden = false;
    manageUsageLink.hidden = true;
    setAiStatus("Continue with ChatGPT and authorize ChatGPT plan usage to enable explanations.");
  } else if (hasRegistration) {
    chatgptLabel.textContent = "ChatGPT signed out";
    chatgptLabel.title = chatgptLabel.textContent;
    chatgptSignInButton.hidden = false;
    chatgptSignInLabel.textContent = "Continue with ChatGPT";
    chatgptAddAccountButton.hidden = false;
    chatgptSignOutButton.hidden = true;
    manageUsageLink.hidden = true;
    setAiStatus("Continue with ChatGPT to sign back in, or add another ChatGPT account.");
  } else {
    chatgptLabel.textContent = "ChatGPT plan not connected";
    chatgptLabel.title = chatgptLabel.textContent;
    chatgptSignInButton.hidden = false;
    chatgptSignInLabel.textContent = "Continue with ChatGPT";
    chatgptAddAccountButton.hidden = true;
    chatgptSignOutButton.hidden = true;
    manageUsageLink.hidden = true;
    setAiStatus("Sign in with ChatGPT to use eligible ChatGPT plan usage for explanations.");
  }

  const accounts = state.accounts || [];
  chatgptAccountSelect.replaceChildren();
  for (const account of accounts) {
    const option = document.createElement("option");
    option.value = account.clientId;
    option.textContent = account.email + (account.connected ? " · plan enabled" : account.signedIn ? " · plan permission needed" : " · signed out");
    option.selected = account.clientId === state.activeClientId;
    chatgptAccountSelect.append(option);
  }
  chatgptAccountSelect.hidden = accounts.length < 2;
  if (accounts.length > 1) chatgptLabel.hidden = true;
  else chatgptLabel.hidden = false;
  if (activeAccount && !connected && activeAccount.planEnabled) {
    chatgptLabel.textContent = "ChatGPT sign-in needs renewal";
  }

  explainButton.disabled = !connected || !latestAnalysisOutput || !modelCatalogReady;
  if (!connected) modelCatalogReady = false;
}

async function loadChatGPTModels() {
  modelCatalogReady = false;
  aiModelSelect.replaceChildren();
  aiModelSelect.disabled = true;
  explainButton.disabled = true;
  if (!authState?.connected) return;

  try {
    const response = await fetch("/api/chatgpt/models", { cache: "no-store" });
    const data = await readResponse(response);
    if (!response.ok) throw new Error(data.error || "Could not load models for this ChatGPT account.");
    const models = Array.isArray(data.models) ? data.models : [];
    const model = models.find((candidate) => candidate.slug === CHATGPT_MODEL);
    if (!model) throw new Error("GPT-6 Luna is not available to this ChatGPT account. Sign in with an account that has access to GPT-6 Luna.");
    const option = document.createElement("option");
    option.value = model.slug;
    option.textContent = "GPT-6 Luna · Max reasoning";
    aiModelSelect.append(option);
    modelCatalogReady = true;
    explainButton.disabled = !latestAnalysisOutput;
    setAiStatusWithUsageLink("Using GPT-6 Luna with max reasoning effort through your ChatGPT plan.", "success");
  } catch (error) {
    setAiStatus(error.message, "error");
  }
}

async function refreshChatGPTStatus() {
  try {
    const response = await fetch("/api/chatgpt/status", { cache: "no-store" });
    const data = await readResponse(response);
    if (!response.ok) throw new Error(data.error || "Could not read ChatGPT sign-in status.");
    renderChatGPTStatus(data);
    if (data.connected) await loadChatGPTModels();
  } catch (error) {
    chatgptLabel.textContent = "ChatGPT status unavailable";
    setAiStatus(error.message, "error");
  }
}

async function startChatGPTSignIn(newAccount = false) {
  const button = newAccount ? chatgptAddAccountButton : chatgptSignInButton;
  const startingClientId = authState?.activeClientId || null;
  button.disabled = true;
  const label = newAccount ? button : chatgptSignInLabel;
  const oldText = label.textContent;
  label.textContent = "Opening ChatGPT…";
  setAiStatus("Opening the system browser for ChatGPT sign-in. Review the requested permissions there.");
  try {
    const response = await fetch("/api/chatgpt/sign-in", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ newAccount }),
    });
    const data = await readResponse(response);
    if (!response.ok) throw new Error(data.error || "Could not start ChatGPT sign-in.");
    setAiStatus("Finish sign-in and authorize ChatGPT plan usage in the browser, then return to this tab.");
    if (authPollTimer) clearInterval(authPollTimer);
    const startedAt = Date.now();
    authPollTimer = setInterval(async () => {
      if (Date.now() - startedAt > 10 * 60 * 1000) {
        clearInterval(authPollTimer);
        authPollTimer = null;
        return;
      }
      if (authPollBusy) return;
      authPollBusy = true;
      await refreshChatGPTStatus();
      authPollBusy = false;
      const connectedSameAccount = !newAccount && authState?.activeClientId === startingClientId && authState?.connected;
      const switchedAccount = newAccount && authState?.activeClientId && authState.activeClientId !== startingClientId;
      if (connectedSameAccount || switchedAccount) {
        clearInterval(authPollTimer);
        authPollTimer = null;
      }
    }, 2500);
  } catch (error) {
    setAiStatus(error.message, "error");
  } finally {
    button.disabled = false;
    label.textContent = oldText;
  }
}

async function checkConnection() {
  try {
    const response = await fetch("/api/health", { cache: "no-store" });
    const data = await readResponse(response);
    if (!data.reaAvailable) {
      localIndicator.classList.add("disconnected");
      connectionLabel.textContent = "REA NOT FOUND";
      setStatus("The local site is running, but it cannot find the rea command. Start it from a Terminal where REA is installed.", "error");
      return;
    }
    localIndicator.classList.add("connected");
    connectionLabel.textContent = "REA READY ON THIS MAC";
    setStatus("Local REA connection is ready.", "success");
  } catch {
    localIndicator.classList.add("disconnected");
    connectionLabel.textContent = "CONNECTION ISSUE";
    setStatus("Could not reach the local REA server. Restart it from the launcher.", "error");
  }
}

chatgptSignInButton.addEventListener("click", () => startChatGPTSignIn(false));
chatgptAddAccountButton.addEventListener("click", () => startChatGPTSignIn(true));

chatgptAccountSelect.addEventListener("change", async () => {
  chatgptAccountSelect.disabled = true;
  try {
    const response = await fetch("/api/chatgpt/use-account", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ clientId: chatgptAccountSelect.value }),
    });
    const data = await readResponse(response);
    if (!response.ok) throw new Error(data.error || "Could not switch ChatGPT account.");
    renderChatGPTStatus(data);
    aiOutput.hidden = true;
    aiOutput.textContent = "";
    await loadChatGPTModels();
  } catch (error) {
    setAiStatus(error.message, "error");
    await refreshChatGPTStatus();
  } finally {
    chatgptAccountSelect.disabled = false;
  }
});

chatgptSignOutButton.addEventListener("click", async () => {
  chatgptSignOutButton.disabled = true;
  setAiStatus("Signing out and revoking this ChatGPT session…");
  try {
    const response = await fetch("/api/chatgpt/sign-out", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const data = await readResponse(response);
    if (!response.ok) throw new Error(data.error || "Could not sign out.");
    await refreshChatGPTStatus();
    if (!data.revocationConfirmed) setAiStatus("Signed out on this Mac. OpenAI could not confirm remote revocation; you can disconnect this app in ChatGPT settings.", "error");
  } catch (error) {
    setAiStatus(error.message, "error");
  } finally {
    chatgptSignOutButton.disabled = false;
  }
});

welcomeDismiss.addEventListener("click", () => {
  try { localStorage.setItem("reaChatGPTPlanWelcomeSeen", "yes"); } catch { /* The dialog can still be dismissed without storage. */ }
  welcomeDialog.close();
});

window.addEventListener("focus", () => {
  if (authPollTimer) refreshChatGPTStatus();
});

explainButton.addEventListener("click", async () => {
  const prompt = chatgptPrompt.value.trim();
  if (!latestAnalysisOutput || !aiModelSelect.value) return;
  if (!prompt) {
    setAiStatus("Enter a question for ChatGPT first.", "error");
    chatgptPrompt.focus();
    return;
  }
  explainButton.disabled = true;
  explainButton.querySelector(".button-label").textContent = "Asking ChatGPT…";
  aiOutput.hidden = false;
  aiOutput.textContent = "ChatGPT is reading the REA output and preparing an answer…";
  setAiStatus(latestAnalysisTargetKind === "website"
    ? "Sending your question and the displayed REA output to OpenAI. Captured page text, code, and URLs may be included; the browser capture stays on this Mac."
    : "Sending your question and the displayed REA output to OpenAI. The selected app files remain on this Mac.");
  try {
    const response = await fetch("/api/chatgpt/explain", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ output: latestAnalysisOutput, prompt }),
    });
    const data = await readResponse(response);
    if (!response.ok) {
      if (response.status === 429 || data.code === "usage_limit_reached") {
        const limitError = new Error(data.error || "The ChatGPT usage limit has been reached. Review your plan or this app’s limit in ChatGPT settings.");
        limitError.manageUsage = true;
        throw limitError;
      }
      throw new Error(data.error || "ChatGPT could not answer this question.");
    }
    aiOutput.textContent = data.text || "ChatGPT returned an empty explanation.";
    setAiStatusWithUsageLink("Answer complete. This request used your ChatGPT plan.", "success");
  } catch (error) {
    aiOutput.textContent = error.message;
    if (error.manageUsage) setAiStatusWithUsageLink(error.message, "error");
    else setAiStatus(error.message, "error");
  } finally {
    explainButton.disabled = !authState?.connected || !modelCatalogReady;
    explainButton.querySelector(".button-label").textContent = "Ask ChatGPT";
  }
});

chooseButton.addEventListener("click", async () => {
  chooseButton.disabled = true;
  setStatus("Opening the macOS file picker…");
  try {
    const response = await fetch("/api/select", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const data = await readResponse(response);
    if (!response.ok) throw new Error(data.error || "The file picker could not open.");
    if (data.path) {
      pathInput.value = data.path;
      pathInput.focus();
      setStatus("Target selected. Start the analysis when you’re ready.", "success");
    } else {
      setStatus("Selection cancelled.");
    }
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    chooseButton.disabled = false;
  }
});

async function submitAnalysis(event, targetKind) {
  event.preventDefault();
  const isWebsite = targetKind === "website";
  const value = (isWebsite ? websiteUrlInput.value : pathInput.value).trim();
  const activeButton = isWebsite ? websiteAnalyzeButton : analyzeButton;
  if (!value) {
    setStatus(isWebsite ? "Paste a public website link first." : "Choose an app bundle, app.asar file, or extracted app folder first.", "error");
    (isWebsite ? websiteUrlInput : pathInput).focus();
    return;
  }

  activeButton.disabled = true;
  websiteAnalyzeButton.disabled = true;
  analyzeButton.disabled = true;
  if (!isWebsite) chooseButton.disabled = true;
  activeButton.querySelector(".button-label").textContent = isWebsite ? "Capturing website…" : "Analyzing locally…";
  resultTitle.textContent = isWebsite ? "Capturing public page" : "Inspecting application";
  setResultState("RUNNING", "running");
  emptyState.hidden = true;
  websitePreview.hidden = true;
  websitePreviewImage.removeAttribute("src");
  resultOutput.hidden = false;
  renderAnalysisOutput(isWebsite
    ? "REA is opening the first page in a temporary browser, recording its structure and loaded scripts, then analyzing captured JavaScript.\n"
    : "REA is inventorying and parsing the selected application. Larger apps may take a little while.\n");
  latestAnalysisOutput = "";
  latestDisplayOutput = "";
  latestAnalysisTargetKind = targetKind;
  aiPanel.hidden = true;
  aiOutput.hidden = true;
  aiOutput.textContent = "";
  setAiStatus(authState?.connected ? "Your latest REA results will appear here after analysis." : "Sign in with ChatGPT to ask questions about REA results.");
  setStatus(isWebsite ? "Capturing the public page on this Mac. Keep this tab open until the result appears." : "Running REA locally. Keep this page open until the result appears.");
  copyButton.disabled = true;

  try {
    const response = await fetch(isWebsite ? "/api/analyze-website" : "/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(isWebsite ? { url: value } : { path: value }),
    });
    const data = await readResponse(response);
    if (data.stdout !== undefined || data.stderr !== undefined) {
      const hasWebsiteScreenshot = isWebsite && typeof data.screenshotDataUrl === "string";
      if (hasWebsiteScreenshot) websitePreviewImage.src = data.screenshotDataUrl;
      websitePreview.hidden = !hasWebsiteScreenshot;
      const sections = [];
      if (data.target?.url) sections.push("Website: " + data.target.url);
      if (data.target?.selectedPath) {
        sections.push("Selected: " + data.target.selectedPath);
        if (data.target.path !== data.target.selectedPath) sections.push("Analyzing: " + data.target.path);
        sections.push("Input type: " + data.target.kind);
      }
      sections.push("Exit code: " + (data.exitCode === null ? "unknown" : data.exitCode));
      sections.push("\n--- REA output ---\n");
      sections.push(data.stdout || "(REA returned no standard output.)");
      if (data.stderr) sections.push("\n--- Diagnostics ---\n" + data.stderr);
      if (data.error) sections.push("\n--- Error ---\n" + data.error);
      latestDisplayOutput = sections.join("\n");
      renderAnalysisOutput(latestDisplayOutput, isWebsite ? data.overview : null);
      latestAnalysisOutput = latestDisplayOutput.slice(0, 80000);
      latestAnalysisTargetKind = targetKind;
      aiPanel.hidden = !latestAnalysisOutput;
      const success = response.ok && data.exitCode === 0;
      resultTitle.textContent = success ? (isWebsite ? "Website analysis complete" : "Analysis complete") : "Analysis needs attention";
      setResultState(success ? "COMPLETE" : "CHECK OUTPUT", success ? "complete" : "failed");
      setStatus(success
        ? (isWebsite ? "REA captured the first page and analyzed its retained JavaScript. Review the evidence in the output panel." : "REA finished. Review the evidence in the output panel.")
        : (data.error || "REA returned an error. See the output panel for details."), success ? "success" : "error");
      copyButton.disabled = false;
    } else {
      websitePreview.hidden = true;
      latestDisplayOutput = data.error || JSON.stringify(data, null, 2);
      renderAnalysisOutput(latestDisplayOutput);
      latestAnalysisOutput = "";
      aiPanel.hidden = true;
      resultTitle.textContent = "Analysis needs attention";
      setResultState("CHECK OUTPUT", "failed");
      setStatus(data.error || "The analysis could not be completed.", "error");
      copyButton.disabled = false;
    }
  } catch (error) {
    websitePreview.hidden = true;
    latestDisplayOutput = error.message;
    renderAnalysisOutput(latestDisplayOutput);
    latestAnalysisOutput = "";
    aiPanel.hidden = true;
    resultTitle.textContent = "Connection interrupted";
    setResultState("ERROR", "failed");
    setStatus(error.message, "error");
    copyButton.disabled = false;
  } finally {
    analyzeButton.disabled = false;
    websiteAnalyzeButton.disabled = false;
    chooseButton.disabled = false;
    analyzeButton.querySelector(".button-label").textContent = "Analyze application";
    websiteAnalyzeButton.querySelector(".button-label").textContent = "Analyze website";
    explainButton.disabled = !authState?.connected || !modelCatalogReady || !latestAnalysisOutput;
  }
}

form.addEventListener("submit", (event) => submitAnalysis(event, "application"));
websiteForm.addEventListener("submit", (event) => submitAnalysis(event, "website"));

copyButton.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(latestDisplayOutput);
    setStatus("Output copied to clipboard.", "success");
  } catch {
    setStatus("Clipboard access is unavailable in this browser.", "error");
  }
});

if (window.location.protocol === "file:") {
  document.body.classList.add("file-open");
  fileOpenNotice.hidden = false;
  localIndicator.classList.add("disconnected");
  connectionLabel.textContent = "OPEN THE LOCAL SERVER";
} else {
  checkConnection();
  refreshChatGPTStatus();
}
