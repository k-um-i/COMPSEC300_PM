let dbOpen = false;
let allEntries = [];
let firstRun = true;

document.addEventListener("DOMContentLoaded", function () {
  const toggleButtons = document.querySelectorAll(".toggle-btn");
  toggleButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      btn.classList.toggle("active");
    });
  });
});

function toggleTheme() {
  const checkbox = document.getElementById("themeToggle");
  const theme = checkbox.checked ? "newlight.css" : "newdark.css";
  document.getElementById("theme-style").setAttribute("href", theme);
}

async function checkPasswordStrength(password) {
  strengthIndicator = document.getElementById("strengthIndicator");
  strengthLabel = document.getElementById("passwordStrengthLabel");

  if (password === "") {
    password = document.getElementById("newPassword").value;
  }
  strength = await passStrn(password);

  strengthWidth = (strength / 200) * 100;
  if (strengthWidth > 100) {
    strengthWidth = 100;
  }

  const hue = strengthWidth * 1.2;
  const color = `hsl(${hue}, 100%, 45%)`;
  const formattedStrength = parseFloat(strength).toFixed(3);

  strengthIndicator.style.width = strengthWidth + "%";
  strengthIndicator.style.backgroundColor = color;
  strengthLabel.textContent = `Password Entropy: ${formattedStrength}`;
}

async function toggleDatabase() {
  if (dbOpen) {
    closeDatabase();
  } else {
    openDatabase();
  }
}

async function openDatabase() {
  if (firstRun) {
    xmlString = await fetchDB();
    xmlString = await decodeEscapedXml(xmlString);
    await parseEntries(xmlString);
    firstRun = false;
  }
  dbOpen = true;
  document.getElementById("dbButton").textContent = "Close Database";
  document.getElementById("searchSection").classList.remove("hidden");
  document.getElementById("searchSection").classList.add("visible");
  document.getElementById("addEntrySection").classList.remove("hidden");
  document.getElementById("addEntrySection").classList.add("visible");

  renderEntries(allEntries);
}

function entriesToXML(entries) {
  const escapeXML = (str) =>
    str.replace(
      /[<>&'"]/g,
      (char) =>
        ({
          "<": "&lt;",
          ">": "&gt;",
          "&": "&amp;",
          "'": "&apos;",
          '"': "&quot;",
        })[char],
    );

  let xml = `<PasswordManager>\n`;

  entries.forEach((entry) => {
    xml += `  <Entry>\n`;
    xml += `    <Title>${escapeXML(entry.Title || "")}</Title>\n`;
    xml += `    <Username>${escapeXML(entry.Username || "")}</Username>\n`;
    xml += `    <Email>${escapeXML(entry.Email || "")}</Email>\n`;
    xml += `    <Password>${escapeXML(entry.Password || "")}</Password>\n`;
    xml += `    <URL>${escapeXML(entry.URL || "")}</URL>\n`;
    xml += `    <Notes>${escapeXML(entry.Notes || "")}</Notes>\n`;
    xml += `  </Entry>\n`;
  });

  xml += `</PasswordManager>`;
  return xml;
}

async function closeDatabase() {
  const container = document.getElementById("password-entries");
  container.innerHTML = "";
  dbOpen = false;
  document.getElementById("dbButton").textContent = "Open Database";
  document.getElementById("searchInput").value = "";
  document.getElementById("searchSection").classList.remove("visible");
  document.getElementById("searchSection").classList.add("hidden");
  document.getElementById("addEntrySection").classList.remove("visible");
  document.getElementById("addEntrySection").classList.add("hidden");
}

async function decodeEscapedXml(xmlString) {
  decoded = xmlString
    .replace(/\\u003c/g, "<")
    .replace(/\\u003e/g, ">")
    .replace(/\\n/g, "");
  return decoded.slice(1, -1);
}

async function parseEntries(xmlString) {
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "text/xml");
  const entries = xmlDoc.getElementsByTagName("Entry");
  const parsedEntries = [];

  for (let entry of entries) {
    parsedEntries.push({
      Title: getText(entry, "Title"),
      Username: getText(entry, "Username"),
      Email: getText(entry, "Email"),
      Password: getText(entry, "Password"),
      URL: getText(entry, "URL"),
      Notes: getText(entry, "Notes"),
      LastModified: getText(entry, "LastModified"),
    });
  }

  allEntries = parsedEntries;
}

function getText(parent, tag) {
  const element = parent.getElementsByTagName(tag)[0];
  return element ? element.textContent : "";
}

function updateDatabase() {
  xmlString = entriesToXML(allEntries);
  updateDB(xmlString);
}

function deleteEntry(index) {
  if (confirm("Are you sure you want to delete this entry?")) {
    allEntries.splice(index, 1);
    updateDatabase();
    renderEntries(allEntries);
  }
}

function addEntry() {
  const newEntry = {
    Title: document.getElementById("newTitle").value,
    Username: document.getElementById("newUsername").value,
    Email: document.getElementById("newEmail").value,
    Password: document.getElementById("newPassword").value,
    URL: document.getElementById("newURL").value,
    Notes: document.getElementById("newNotes").value,
  };

  allEntries.push(newEntry);
  updateDatabase();
  renderEntries(allEntries);

  document.getElementById("newTitle").value = "";
  document.getElementById("newUsername").value = "";
  document.getElementById("newEmail").value = "";
  document.getElementById("newPassword").value = "";
  document.getElementById("newURL").value = "";
  document.getElementById("newNotes").value = "";
  document.getElementById("strengthIndicator").style.width = "0%";
  document.getElementById("passwordStrengthLabel").textContent =
    "Password Entropy: 0";
}

function renderEntries(entries) {
  const container = document.getElementById("password-entries");
  container.innerHTML = ""; // Clear previous entries if any

  entries.forEach((entry, index) => {
    const details = document.createElement("details");
    details.className = "entry";
    const summary = document.createElement("summary");
    summary.textContent = entry.Title;

    const content = `
            <p><strong>Username:</strong> ${entry.Username}</p>
            <p><strong>Email:</strong> ${entry.Email}</p>
            <p><strong>Password:</strong> ${entry.Password}</p>
            <p><strong>URL:</strong> ${entry.URL}</p>
            <p><strong>Notes:</strong> ${entry.Notes}</p>
            <button onclick="deleteEntry(${index})">Delete Entry</button>
          `;

    details.appendChild(summary);
    details.innerHTML += content;

    container.appendChild(details);
  });
}

function filterEntries() {
  const query = document.getElementById("searchInput").value.toLowerCase();
  const filtered = allEntries.filter((entry) =>
    entry.Title.toLowerCase().includes(query),
  );
  renderEntries(filtered);
}

async function generatePassword() {
  const length = parseInt(document.getElementById("passwordLength").value);
  const activeSets = document.querySelectorAll(".toggle-btn.active");
  let charset = "";

  activeSets.forEach((btn) => {
    switch (btn.dataset.set) {
      case "uppercase":
        charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        break;
      case "lowercase":
        charset += "abcdefghijklmnopqrstuvwxyz";
        break;
      case "numbers":
        charset += "0123456789";
        break;
      case "symbols":
        charset += "!@#$%^*()-_=+[]{}?/|";
        break;
    }
  });

  if (charset.length === 0) {
    console.log("Failed to generate password, no character sets selected.");
    return;
  }

  await setCharset(charset);
  let password = await genPass(length);
  await checkPasswordStrength(password);
  document.getElementById("newPassword").value = password.slice(1, -1);
}
