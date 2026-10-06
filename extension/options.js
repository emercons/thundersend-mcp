// `browser` is declared as a global in eslint.config.mjs for the
// extension/ file group.
"use strict";

const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const serverPort = document.getElementById("serverPort");
const connFile = document.getElementById("connFile");
const buildInfo = document.getElementById("buildInfo");
const accountList = document.getElementById("accountList");
const saveBtn = document.getElementById("saveBtn");
const saveStatus = document.getElementById("saveStatus");

const toolList = document.getElementById("toolList");
const saveToolsBtn = document.getElementById("saveToolsBtn");
const saveToolsStatus = document.getElementById("saveToolsStatus");

const currentAuthTokenInput = document.getElementById("currentAuthToken");
const copyAuthTokenBtn = document.getElementById("copyAuthTokenBtn");
const copyAuthTokenStatus = document.getElementById("copyAuthTokenStatus");
const useStableAuthTokenCheckbox = document.getElementById("useStableAuthToken");
const stableAuthTokenControls = document.getElementById("stableAuthTokenControls");
const stableAuthTokenInput = document.getElementById("stableAuthToken");
const generateStableAuthTokenBtn = document.getElementById("generateStableAuthTokenBtn");
const regenerateStableAuthTokenBtn = document.getElementById("regenerateStableAuthTokenBtn");
const stableAuthTokenStatus = document.getElementById("stableAuthTokenStatus");

// BEGIN OPTIONS ACCESS STATE
let currentAccounts = [];
let currentTools = [];
let currentAccountError = "";
let accountAccessChanged = false;
let currentToolError = "";
let toolAccessChanged = false;

// CRUD labels for sub-group headers
const CRUD_LABELS = { read: "Read", create: "Create" };
// END OPTIONS ACCESS STATE

// BEGIN OPTIONS SERVER STATUS
const retryServerBtn = document.getElementById("retryServerBtn");

async function loadServerInfo() {
  try {
    const info = await browser.mcpServer.getServerInfo();
    retryServerBtn.hidden = info.running || !info.lastError;
    if (info.running) {
      statusDot.className = "status-dot running";
      statusText.textContent = "Running";
      serverPort.textContent = info.port || "--";
      connFile.textContent = info.connectionFile || "--";
    } else {
      statusDot.className = "status-dot stopped";
      statusText.textContent = info.lastError ? "Failed to start: " + info.lastError : "Not running";
      serverPort.textContent = "--";
      connFile.textContent = "--";
    }
    if (info.buildVersion) {
      // Parse git describe: "v0.2.0-7-g1461f1a+dirty" -> tag, commits, hash, dirty
      const m = info.buildVersion.match(/^(v[\d.]+)(?:-(\d+)-g([0-9a-f]+))?(\+dirty)?$/);
      let display;
      if (m) {
        const [, tag, commits, hash, dirty] = m;
        display = tag;
        if (commits && commits !== "0") display += ` +${commits}`;
        display += ` (${hash || tag})`;
        if (dirty) {
          display += " +dirty";
          if (info.buildDate) {
            display += " " + info.buildDate.replace("T", " ").replace(/\.\d+Z$/, " UTC");
          }
        }
      } else {
        display = info.buildVersion;
      }
      buildInfo.textContent = display;
    } else {
      buildInfo.textContent = "--";
    }
  } catch (e) {
    statusDot.className = "status-dot stopped";
    statusText.textContent = "Error: " + e.message;
    serverPort.textContent = "--";
    connFile.textContent = "--";
  }
}

retryServerBtn.addEventListener("click", async () => {
  retryServerBtn.disabled = true;
  statusText.textContent = "Starting...";
  try {
    const result = await browser.mcpServer.start();
    await loadServerInfo();
    if (result.success) await loadAuthenticationConfig();
  } catch (e) {
    statusDot.className = "status-dot stopped";
    statusText.textContent = "Failed to start: " + e.message;
  } finally {
    retryServerBtn.disabled = false;
  }
});
// END OPTIONS SERVER STATUS

function updateStableAuthTokenControls() {
  stableAuthTokenControls.hidden = !useStableAuthTokenCheckbox.checked;
}

function setStableAuthTokenBusy(busy) {
  useStableAuthTokenCheckbox.disabled = busy;
  stableAuthTokenInput.disabled = busy;
  generateStableAuthTokenBtn.disabled = busy;
  regenerateStableAuthTokenBtn.disabled = busy;
}

function setStableAuthTokenStatus(message, error = false) {
  stableAuthTokenStatus.textContent = message;
  stableAuthTokenStatus.className = error ? "save-status error" : "save-status";
}

async function requestGeneratedAuthToken() {
  const result = await browser.mcpServer.generateAuthToken();
  if (result.error) {
    throw new Error(result.error);
  }
  if (!result.authToken) {
    throw new Error("Generated token was empty");
  }
  return result.authToken;
}

async function saveStableAuthTokenValue(value, successMessage = "Saved.") {
  const stableAuthToken = value.trim();
  setStableAuthTokenStatus("Saving...");
  const result = await browser.mcpServer.setStableAuthToken(stableAuthToken);
  if (result.error) {
    setStableAuthTokenStatus(result.error, true);
    return false;
  }
  stableAuthTokenInput.value = result.stableAuthToken || "";
  setStableAuthTokenStatus(successMessage);
  return true;
}

async function updateStoredStableAuthToken(value, successMessage) {
  setStableAuthTokenBusy(true);
  try {
    await saveStableAuthTokenValue(value, successMessage);
  } catch (e) {
    setStableAuthTokenStatus("Error: " + e.message, true);
  }
  setStableAuthTokenBusy(false);
  updateStableAuthTokenControls();
}

async function generateAndStoreStableAuthToken(successMessage) {
  setStableAuthTokenBusy(true);
  try {
    const token = await requestGeneratedAuthToken();
    stableAuthTokenInput.value = token;
    await saveStableAuthTokenValue(token, successMessage);
  } catch (e) {
    setStableAuthTokenStatus("Error: " + e.message, true);
  }
  setStableAuthTokenBusy(false);
  updateStableAuthTokenControls();
}

async function loadAuthenticationConfig() {
  try {
    const [current, stable] = await Promise.all([
      browser.mcpServer.getCurrentAuthToken(),
      browser.mcpServer.getStableAuthToken(),
    ]);
    currentAuthTokenInput.value = current.authToken || "";
    copyAuthTokenBtn.disabled = !currentAuthTokenInput.value;
    copyAuthTokenStatus.textContent = "";
    copyAuthTokenStatus.className = "save-status";

    stableAuthTokenInput.value = stable.stableAuthToken || "";
    useStableAuthTokenCheckbox.checked = !!stableAuthTokenInput.value;
    updateStableAuthTokenControls();
    setStableAuthTokenStatus("");
  } catch (e) {
    copyAuthTokenStatus.textContent = "Error loading token: " + e.message;
    copyAuthTokenStatus.className = "save-status error";
    setStableAuthTokenStatus("Error loading setting: " + e.message, true);
  }
}

copyAuthTokenBtn.addEventListener("click", async () => {
  copyAuthTokenStatus.textContent = "";
  copyAuthTokenStatus.className = "save-status";
  copyAuthTokenBtn.disabled = true;
  try {
    await navigator.clipboard.writeText(currentAuthTokenInput.value);
    copyAuthTokenStatus.textContent = "Copied.";
  } catch (e) {
    copyAuthTokenStatus.textContent = "Error: " + e.message;
    copyAuthTokenStatus.className = "save-status error";
  }
  copyAuthTokenBtn.disabled = !currentAuthTokenInput.value;
});

useStableAuthTokenCheckbox.addEventListener("change", async () => {
  updateStableAuthTokenControls();
  if (useStableAuthTokenCheckbox.checked) {
    if (!stableAuthTokenInput.value.trim()) {
      await generateAndStoreStableAuthToken("Generated and saved.");
    } else {
      await updateStoredStableAuthToken(stableAuthTokenInput.value, "Saved.");
    }
  } else {
    stableAuthTokenInput.value = "";
    await updateStoredStableAuthToken("", "Stable token cleared.");
  }
});

stableAuthTokenInput.addEventListener("change", async () => {
  if (!useStableAuthTokenCheckbox.checked) {
    return;
  }
  if (!stableAuthTokenInput.value.trim()) {
    await generateAndStoreStableAuthToken("Generated and saved.");
  } else {
    await updateStoredStableAuthToken(stableAuthTokenInput.value, "Saved.");
  }
});

generateStableAuthTokenBtn.addEventListener("click", async () => {
  await generateAndStoreStableAuthToken("Generated and saved.");
});

regenerateStableAuthTokenBtn.addEventListener("click", async () => {
  await generateAndStoreStableAuthToken("Regenerated and saved.");
});

// BEGIN OPTIONS ACCOUNT ACCESS
async function loadAccountAccess() {
  saveBtn.disabled = true;
  accountAccessChanged = false;
  try {
    const data = await browser.mcpServer.getAccountAccessConfig();
    currentAccounts = data.accounts || [];
    currentAccountError = data.mode === "error"
      ? (data.error || "Invalid account access configuration.") + " Access is blocked. Select allowed accounts and save to replace this setting."
      : "";
    saveStatus.textContent = currentAccountError;
    saveStatus.className = currentAccountError ? "save-status error" : "save-status";

    if (currentAccounts.length === 0) {
      accountList.innerHTML = "<li>No accounts found.</li>";
      return;
    }

    accountList.innerHTML = "";
    for (const acct of currentAccounts) {
      const li = document.createElement("li");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.id = "acct-" + acct.id;
      checkbox.value = acct.id;
      checkbox.checked = acct.allowed;
      checkbox.addEventListener("change", onAccountChange);

      const label = document.createElement("label");
      label.htmlFor = checkbox.id;
      label.textContent = acct.name;

      const typeSpan = document.createElement("span");
      typeSpan.className = "account-type";
      typeSpan.textContent = acct.type;
      label.appendChild(typeSpan);

      li.appendChild(checkbox);
      li.appendChild(label);
      accountList.appendChild(li);
    }
  } catch (e) {
    accountList.innerHTML = "";
    const li = document.createElement("li");
    li.textContent = "Error loading accounts: " + e.message;
    accountList.appendChild(li);
  }
}

function onAccountChange() {
  const checkboxes = accountList.querySelectorAll('input[type="checkbox"]');
  accountAccessChanged = [...checkboxes].some(cb =>
    cb.checked !== !!currentAccounts.find(acct => acct.id === cb.value)?.allowed
  );
  saveBtn.disabled = !accountAccessChanged;
  saveStatus.textContent = currentAccountError;
  saveStatus.className = currentAccountError ? "save-status error" : "save-status";
}

saveBtn.addEventListener("click", async () => {
  if (!accountAccessChanged) return;
  saveBtn.disabled = true;
  saveStatus.textContent = "";
  saveStatus.className = "save-status";

  const checkboxes = accountList.querySelectorAll('input[type="checkbox"]');
  const checked = [];
  let allChecked = true;
  for (const cb of checkboxes) {
    if (cb.checked) {
      checked.push(cb.value);
    } else {
      allChecked = false;
    }
  }

  if (checked.length === 0) {
    saveStatus.textContent = "Select at least one account. The existing access setting has not changed.";
    saveStatus.className = "save-status error";
    saveBtn.disabled = false;
    return;
  }

  // If all are checked, send empty array (= allow all)
  const allowedIds = allChecked ? [] : checked;

  try {
    const result = await browser.mcpServer.setAccountAccess(allowedIds);
    if (result.error) {
      saveStatus.textContent = result.error;
      saveStatus.className = "save-status error";
    } else {
      saveStatus.textContent = "Saved.";
      await loadAccountAccess();
    }
  } catch (e) {
    saveStatus.textContent = "Error: " + e.message;
    saveStatus.className = "save-status error";
  }
  saveBtn.disabled = !accountAccessChanged;
});
// END OPTIONS ACCOUNT ACCESS

// BEGIN OPTIONS TOOL ACCESS
async function loadToolAccess() {
  saveToolsBtn.disabled = true;
  toolAccessChanged = false;
  try {
    const data = await browser.mcpServer.getToolAccessConfig();
    currentTools = data.tools || [];
    const groupLabels = data.groups || {};
    currentToolError = data.mode === "error"
      ? (data.error || "Invalid tool access configuration.") + " Optional tools are blocked. Change tool access and save to replace this setting."
      : "";
    saveToolsStatus.textContent = currentToolError;
    saveToolsStatus.className = currentToolError ? "save-status error" : "save-status";

    if (currentTools.length === 0) {
      toolList.innerHTML = "<li>No tools found.</li>";
      return;
    }

    toolList.innerHTML = "";
    let currentGroup = null;
    let currentCrud = null;

    for (const tool of currentTools) {
      const group = tool.group || "other";
      const crud = tool.crud || "other";

      if (group !== currentGroup) {
        currentGroup = group;
        currentCrud = null;
        const header = document.createElement("li");
        header.className = "tool-group-header";
        header.textContent = groupLabels[group] || group.charAt(0).toUpperCase() + group.slice(1);
        toolList.appendChild(header);
      }

      if (crud !== currentCrud) {
        currentCrud = crud;
        const subHeader = document.createElement("li");
        subHeader.className = "tool-crud-header";
        subHeader.textContent = CRUD_LABELS[crud] || crud.charAt(0).toUpperCase() + crud.slice(1);
        toolList.appendChild(subHeader);
      }

      const li = document.createElement("li");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.id = "tool-" + tool.name;
      checkbox.value = tool.name;
      checkbox.checked = tool.enabled;
      if (tool.undisableable) {
        checkbox.disabled = true;
      }
      checkbox.addEventListener("change", onToolChange);

      const label = document.createElement("label");
      label.htmlFor = checkbox.id;
      label.textContent = tool.name;
      if (tool.undisableable) {
        const lockSpan = document.createElement("span");
        lockSpan.className = "account-type";
        lockSpan.textContent = "required";
        label.appendChild(lockSpan);
      }

      li.appendChild(checkbox);
      li.appendChild(label);
      toolList.appendChild(li);
    }
  } catch (e) {
    toolList.innerHTML = "";
    const li = document.createElement("li");
    li.textContent = "Error loading tools: " + e.message;
    toolList.appendChild(li);
  }
}

function onToolChange() {
  const checkboxes = toolList.querySelectorAll('input[type="checkbox"]');
  toolAccessChanged = [...checkboxes].some(cb =>
    !cb.disabled && cb.checked !== !!currentTools.find(tool => tool.name === cb.value)?.enabled
  );
  saveToolsBtn.disabled = !toolAccessChanged;
  saveToolsStatus.textContent = currentToolError;
  saveToolsStatus.className = currentToolError ? "save-status error" : "save-status";
}

saveToolsBtn.addEventListener("click", async () => {
  if (!toolAccessChanged) return;
  saveToolsBtn.disabled = true;
  saveToolsStatus.textContent = "";
  saveToolsStatus.className = "save-status";

  const checkboxes = toolList.querySelectorAll('input[type="checkbox"]');
  const disabled = [];
  for (const cb of checkboxes) {
    if (!cb.checked && !cb.disabled) {
      disabled.push(cb.value);
    }
  }

  try {
    const result = await browser.mcpServer.setToolAccess(disabled);
    if (result.error) {
      saveToolsStatus.textContent = result.error;
      saveToolsStatus.className = "save-status error";
    } else {
      saveToolsStatus.textContent = "Saved.";
      await loadToolAccess();
    }
  } catch (e) {
    saveToolsStatus.textContent = "Error: " + e.message;
    saveToolsStatus.className = "save-status error";
  }
  saveToolsBtn.disabled = !toolAccessChanged;
});
// END OPTIONS TOOL ACCESS

const blockSkipReviewCheckbox = document.getElementById("blockSkipReview");
const saveSkipReviewBtn = document.getElementById("saveSkipReviewBtn");
const saveSkipReviewStatus = document.getElementById("saveSkipReviewStatus");

async function loadSkipReviewPref() {
  try {
    const { blockSkipReview } = await browser.mcpServer.getBlockSkipReview();
    blockSkipReviewCheckbox.checked = !!blockSkipReview;
    saveSkipReviewBtn.disabled = false;
    saveSkipReviewStatus.textContent = "";
  } catch (e) {
    saveSkipReviewStatus.textContent = "Error loading setting: " + e.message;
    saveSkipReviewStatus.className = "save-status error";
  }
}

saveSkipReviewBtn.addEventListener("click", async () => {
  saveSkipReviewBtn.disabled = true;
  saveSkipReviewStatus.textContent = "Saving...";
  saveSkipReviewStatus.className = "save-status";
  try {
    const result = await browser.mcpServer.setBlockSkipReview(blockSkipReviewCheckbox.checked);
    if (result.error) {
      saveSkipReviewStatus.textContent = result.error;
      saveSkipReviewStatus.className = "save-status error";
    } else {
      saveSkipReviewStatus.textContent = "Saved.";
    }
  } catch (e) {
    saveSkipReviewStatus.textContent = "Error: " + e.message;
    saveSkipReviewStatus.className = "save-status error";
  }
  saveSkipReviewBtn.disabled = false;
});

loadServerInfo().catch(e => console.error("thundersend-mcp options:", "loadServerInfo failed:", e));
loadAuthenticationConfig().catch(e => console.error("thundersend-mcp options:", "loadAuthenticationConfig failed:", e));
loadAccountAccess().catch(e => console.error("thundersend-mcp options:", "loadAccountAccess failed:", e));
loadToolAccess().catch(e => console.error("thundersend-mcp options:", "loadToolAccess failed:", e));
loadSkipReviewPref().catch(e => console.error("thundersend-mcp options:", "loadSkipReviewPref failed:", e));

const listenAllCheckbox = document.getElementById("listenAll");
const listenAllWarning = document.getElementById("listenAllWarning");
const saveListenAllBtn = document.getElementById("saveListenAllBtn");
const saveListenAllStatus = document.getElementById("saveListenAllStatus");

async function loadListenAllPref() {
  try {
    const { listenAll } = await browser.mcpServer.getListenAll();
    listenAllCheckbox.checked = !!listenAll;
    listenAllWarning.style.display = listenAllCheckbox.checked ? "block" : "none";
    saveListenAllBtn.disabled = false;
    saveListenAllStatus.textContent = "";
  } catch (e) {
    saveListenAllStatus.textContent = "Error loading setting: " + e.message;
    saveListenAllStatus.className = "save-status error";
  }
}

listenAllCheckbox.addEventListener("change", () => {
  listenAllWarning.style.display = listenAllCheckbox.checked ? "block" : "none";
});

// BEGIN OPTIONS LISTEN ALL SAVE
saveListenAllBtn.addEventListener("click", async () => {
  saveListenAllBtn.disabled = true;
  saveListenAllStatus.textContent = "Saving...";
  saveListenAllStatus.className = "save-status";
  try {
    const result = await browser.mcpServer.setListenAll(listenAllCheckbox.checked);
    if (result.error) {
      saveListenAllStatus.textContent = result.error;
      saveListenAllStatus.className = "save-status error";
    } else {
      saveListenAllStatus.textContent = "Saved.";
    }
  } catch (e) {
    saveListenAllStatus.textContent = "Error: " + e.message;
    saveListenAllStatus.className = "save-status error";
  }
  await loadServerInfo();
  saveListenAllBtn.disabled = false;
});
// END OPTIONS LISTEN ALL SAVE

loadListenAllPref();
