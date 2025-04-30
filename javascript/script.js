// Initialize required global variables
let dbOpen = false;
let allEntries = [];
let filtered = [];
let firstRun = true;

// Event listener for toggle buttons
document.addEventListener("DOMContentLoaded", function () {
  const toggleButtons = document.querySelectorAll(".toggle-btn");
  toggleButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      btn.classList.toggle("active");
    });
  });
});

// Event for switching between dark/light theme
function toggleTheme() {
  const checkbox = document.getElementById("themeToggle");
  const theme = checkbox.checked ? "themes/newlight.css" : "themes/newdark.css";
  document.getElementById("theme-style").setAttribute("href", theme);
}

// Function for checking password strength
async function checkPasswordStrength(password) {
  // Fetch password strength info elements
  strengthIndicator = document.getElementById("strengthIndicator");
  strengthLabel = document.getElementById("passwordStrengthLabel");

  // Fetch password from newPassword element if not provided
  if (password === "") {
    password = document.getElementById("newPassword").value;
  }

  // Get strength by calling go function passStrn() (gui.go)
  strength = await passStrn(password);

  // Calculation for setting strengthIndicator width %
  strengthWidth = (strength / 200) * 100;
  if (strengthWidth > 100) {
    strengthWidth = 100;
  }

  // Calculation for setting strengthIndicator color
  const hue = strengthWidth * 1.2;
  const color = `hsl(${hue}, 100%, 45%)`;
  const formattedStrength = parseFloat(strength).toFixed(3);

  // Set width, color and label
  strengthIndicator.style.width = strengthWidth + "%";
  strengthIndicator.style.backgroundColor = color;
  strengthLabel.textContent = `Password Entropy: ${formattedStrength}`;
}

// Function for toggling database between open and closed
async function toggleDatabase() {
  if (dbOpen) {
    closeDatabase();
  } else {
    openDatabase();
  }
}

// Function for opening database view
async function openDatabase() {
  // Fetch and parse DB contents from backend if first run
  if (firstRun) {
    xmlString = await fetchDB();
    xmlString = await decodeUnicodeEscapes(xmlString);
    console.log(xmlString);
    await parseEntries(xmlString);
    firstRun = false;
  }

  // Set DB to open and toggle required elements to visible
  dbOpen = true;
  document.getElementById("dbButton").textContent = "Close Database";
  document.getElementById("searchSection").classList.remove("hidden");
  document.getElementById("searchSection").classList.add("visible");
  document.getElementById("addEntrySection").classList.remove("hidden");
  document.getElementById("addEntrySection").classList.add("visible");

  // Render all password entries
  filterEntries();
}

// Function for converting entries to XML format
function entriesToXML(entries) {
  // escapeXML function to prevent XML injection into the database.
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

  // Initialize XML string
  let xml = `<PasswordManager>\n`;

  // Iterate through entries and save info to XML string
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

  // Finalize and return XML string
  xml += `</PasswordManager>`;
  return xml;
}

// Function for closing the database view
async function closeDatabase() {
  // Empty entry container and set all required elements to hidden
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

// Function for decoding escaped characters received from the backend
async function decodeUnicodeEscapes(str) {
  decoded = str.replace(/\\u[\dA-Fa-f]{4}/g, (match) => {
    return String.fromCharCode(parseInt(match.replace("\\u", ""), 16));
  });
  decoded = decoded.replace(/\\n/g, "");
  return decoded.slice(1, -1);
}

// Function for parsing entries from xmlString
async function parseEntries(xmlString) {
  // Initialize parser and entries variables
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, "text/xml");
  const entries = xmlDoc.getElementsByTagName("Entry");
  const parsedEntries = [];

  // Iterate through found entries and save text contents from each tag
  for (let entry of entries) {
    parsedEntries.push({
      Title: getText(entry, "Title"),
      Username: getText(entry, "Username"),
      Email: getText(entry, "Email"),
      Password: getText(entry, "Password"),
      URL: getText(entry, "URL"),
      Notes: getText(entry, "Notes"),
    });
  }

  // Set entries to allEntries and filtered
  allEntries = parsedEntries;
  const query = document.getElementById("searchInput").value.toLowerCase();
  filtered = allEntries
    .map((entry, i) => ({ entry, index: i }))
    .filter(({ entry }) => entry.Title.toLowerCase().includes(query));
}

// Function for extracting text contents from entry based on tag
function getText(parent, tag) {
  const element = parent.getElementsByTagName(tag)[0];
  return element ? element.textContent : "";
}

// Function for updating changes to database file
function updateDatabase() {
  // Convert entries to xmlString and call go function updateDB() (gui.go)
  xmlString = entriesToXML(allEntries);
  updateDB(xmlString);
}

// Function for deleting an existing entry
function deleteEntry(index) {
  // Prompt for confirmation from user
  if (confirm("Are you sure you want to delete this entry?")) {
    // Remove entry from allEntries and update database contents
    allEntries.splice(index, 1);
    updateDatabase();
    filterEntries();
  }
}

// Function for adding a new entry
function addEntry() {
  // Initialize new entry variable based on information provided
  const newEntry = {
    Title: sanitizeInput(document.getElementById("newTitle").value),
    Username: sanitizeInput(document.getElementById("newUsername").value),
    Email: sanitizeInput(document.getElementById("newEmail").value),
    Password: sanitizeInput(document.getElementById("newPassword").value),
    URL: sanitizeInput(document.getElementById("newURL").value),
    Notes: sanitizeInput(document.getElementById("newNotes").value),
  };

  if (newEntry.Title === "") {
    alert("Title is required when adding an entry.");
    return;
  }

  // Add new entry to allEntries and update database contents
  allEntries.push(newEntry);
  updateDatabase();
  filterEntries();

  // Empty new entry information fields from frontend
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

// Function for sanitizing user input
function sanitizeInput(str) {
  return str.replace(/[<>&'"]/g, (match) => {
    const sanitizeChars = {
      "<": "&lt;",
      ">": "&gt;",
      "&": "&amp;",
      "'": "&apos;",
      '"': "&quot;",
    };
    return sanitizeChars[match];
  });
}

// Function for rendering all password entries
function renderEntries(entries) {
  // Fetch and empty container element
  const container = document.getElementById("password-entries");
  container.innerHTML = ""; // Clear previous entries if any

  // Iterate through existing entries
  entries.forEach(({ entry, index }) => {
    // Create elements for entry details and summary
    const details = document.createElement("details");
    details.className = "entry";

    const summary = document.createElement("summary");
    summary.innerHTML = `
      ${entry.Title}
      <button class="copy-btn" onclick="copyPassword(${index}, this)">Copy Password</button>
    `;

    // Add fields with content stored to the entry details.
    let content = "";
    if (entry.Username != "") {
      content += `<p><strong>Username:</strong> ${entry.Username}</p>`;
    }
    if (entry.Email != "") {
      content += `<p><strong>Email:</strong> ${entry.Email}</p>`;
    }
    if (entry.Password != "") {
      content += `<p><strong>Password:</strong> ${entry.Password}</p>`;
    }
    if (entry.URL != "") {
      content += `<p><strong>URL:</strong> ${entry.URL}</p>`;
    }
    if (entry.Notes != "") {
      content += `<p><strong>Notes:</strong> ${entry.Notes}</p>`;
    }
    // Add 'Delete Entry' button.
    content += `<button onclick="deleteEntry(${index})">Delete Entry</button>`;

    // Append summary to details and details to container
    details.appendChild(summary);
    details.innerHTML += content;
    container.appendChild(details);
  });
}

// Function for copying entry password
function copyPassword(index, btn) {
  // Fetch password from specific entry
  const password = allEntries[index].Password;

  // Write password to clipboard
  navigator.clipboard.writeText(password).then(() => {
    // Change button to 'Copied' for 3 seconds then return to normal
    const originalText = btn.textContent;
    btn.textContent = "Copied!";
    btn.disabled = true;
    setTimeout(() => {
      btn.textContent = originalText;
      btn.disabled = false;
    }, 3000);
  });
}

// Function for filtering entries based on search
function filterEntries() {
  // Fetch query
  const query = document.getElementById("searchInput").value.toLowerCase();
  // Filter through allEntries and save to filtered
  filtered = allEntries
    .map((entry, i) => ({ entry, index: i }))
    .filter(({ entry }) => entry.Title.toLowerCase().includes(query));
  renderEntries(filtered);
}

// Function for generating secure password
async function generatePassword() {
  // Fetch password generation settings
  const length = parseInt(document.getElementById("passwordLength").value);
  const activeSets = document.querySelectorAll(".toggle-btn.active");
  let charset = "";

  // Create character set based on settings
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

  // Confirm that at least one character set was selected
  if (charset.length === 0) {
    console.log("Failed to generate password, no character sets selected.");
    return;
  }

  // Send character set to backend and generate password using go function genPass() (gui.go)
  await setCharset(charset);
  let password = await genPass(length);
  // Check generated password strength and send it to password field
  await checkPasswordStrength(password);
  document.getElementById("newPassword").value = password.slice(1, -1);
}
