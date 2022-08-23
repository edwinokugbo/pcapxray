const hamburger = document.getElementById("hamburger"),
  dropButton = document.getElementById("dropbtn"),
  mainElement = document.querySelector("main"),
  pcapFilePath = document.querySelector("#pcap-path-input"),
  pcapPathButt = document.querySelector("#pcap-path-butt");

hostsTable = document.querySelector("#hosts-table");
packetsTable = document.querySelector("#packets-table");
packetsMap = document.querySelector("#packets-map");
packetsInteractive = document.querySelector("#packets-interactive");

hostsTableButt = document.querySelector("#hosts-table-butt");
packetsTableButt = document.querySelector("#packets-table-butt");
packetsMapButt = document.querySelector("#packets-map-butt");
packetsInteractiveButt = document.querySelector("#packets-interactive-butt");

settingsButt = document.querySelector("#toggle-settings");
settingsBox = document.querySelector("#settings-box");

// var navMenu = document.getElementById("nav-menu"),
//   navDropMenu = document.getElementById("nav-drop-menu");

// function toggleMenu() {
//   navMenu.classList.toggle("show");
// }

// function dropMenu() {
//   navDropMenu.classList.toggle("show");
// }

// function linkMain() {
//   if (navDropMenu.classList.contains("show")) {
//     navDropMenu.classList.remove("show");
//   } else if (navMenu.classList.contains("show")) {
//     navMenu.classList.remove("show");
//   } else {
//     location.href = "#/";
//   }
// }

// hamburger.addEventListener("click", toggleMenu);
// dropButton.addEventListener("click", dropMenu);
// mainElement.addEventListener("click", linkMain);

// var newChoiceButt = document.querySelector("#new-choice-butt");
// var choiceBox = document.querySelector("#new-choice-box");

// newChoiceButt.addEventListener("click", function () {
//   if (choiceBox.style.display == "" || choiceBox.style.display == "none") {
//     choiceBox.style.display = "block";
//   } else {
//     choiceBox.style.display = "none";
//   }
// });

// pcapPathButt.addEventListener("change", function () {
//   alert("nice");
// });

settingsButt.addEventListener("click", function () {
  if (settingsBox.style.display === "none") {
    settingsBox.style.display = "block";
  } else {
    settingsBox.style.display = "none";
  }
});

hostsTableButt.addEventListener("click", function () {
  packetsMap.style.display = "none";
  packetsInteractive.style.display = "none";
  packetsTable.style.display = "none";
  hostsTable.style.display = "block";
});

packetsTableButt.addEventListener("click", function () {
  packetsMap.style.display = "none";
  packetsInteractive.style.display = "none";
  hostsTable.style.display = "none";
  packetsTable.style.display = "block";
});

packetsMapButt.addEventListener("click", function () {
  hostsTable.style.display = "none";
  packetsTable.style.display = "none";
  packetsInteractive.style.display = "none";
  packetsMap.style.display = "block";
});

packetsInteractiveButt.addEventListener("click", function () {
  hostsTable.style.display = "none";
  packetsTable.style.display = "none";
  packetsMap.style.display = "none";
  packetsInteractive.style.display = "block";
});
