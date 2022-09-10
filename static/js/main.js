const hamburger = document.getElementById("hamburger"),
  dropButton = document.getElementById("dropbtn"),
  mainElement = document.querySelector("main"),
  pcapFilePath = document.querySelector("#pcap-path-input"),
  pcapPathButt = document.querySelector("#pcap-path-butt");

  pcapBrowseButt = document.querySelector("#pcap-browse-butt");

hostsTable = document.querySelector("#hosts-table");
packetsTable = document.querySelector("#packets-table");
packetsMap = document.querySelector("#packets-map");
packetsInteractive = document.querySelector("#packets-interactive");
packetsInteractiveTwo = document.querySelector("#packets-interactive-two");
progressIndicator = document.querySelector("#progress-indicator");

hostsTableButt = document.querySelector("#hosts-table-butt");
packetsTableButt = document.querySelector("#packets-table-butt");
packetsMapButt = document.querySelector("#packets-map-butt");
packetsInteractiveButt = document.querySelector("#packets-interactive-butt");
packetsInteractiveButtTwo = document.querySelector("#packets-interactive-butt-two");

settingsBox = document.querySelector("#settings-box");

if (hostsTableButt != null) {
    hostsTableButt.addEventListener("click", function () {
      packetsMap.style.display = "none";
      packetsInteractive.style.display = "none";
      packetsTable.style.display = "none";
      hostsTable.style.display = "block";
    });

    packetsTableButt.addEventListener("click", function () {
      packetsMap.style.display = "none";
      packetsInteractive.style.display = "none";
      packetsInteractiveTwo.style.display = "none";
      hostsTable.style.display = "none";
      packetsTable.style.display = "block";
    });

    packetsMapButt.addEventListener("click", function () {
      hostsTable.style.display = "none";
      packetsTable.style.display = "none";
      packetsInteractive.style.display = "none";
      packetsInteractiveTwo.style.display = "none";
      packetsMap.style.display = "block";
    });

    packetsInteractiveButt.addEventListener("click", function () {
      hostsTable.style.display = "none";
      packetsTable.style.display = "none";
      packetsMap.style.display = "none";
      packetsInteractiveTwo.style.display = "none";
      packetsInteractive.style.display = "block";
    });

    packetsInteractiveButtTwo.addEventListener("click", function () {
      hostsTable.style.display = "none";
      packetsTable.style.display = "none";
      packetsMap.style.display = "none";
      packetsInteractive.style.display = "none";
      packetsInteractiveTwo.style.display = "block";
    });

    pcapBrowseButt.addEventListener("click", function () {
      progressIndicator.style.display = "block";
    });
}

aboutFrame = document.querySelector('#about-frame');
showAbout = document.querySelector('#show-about');
closeAbout = document.querySelector('#close-about');

showAbout.addEventListener('click', function() {
    aboutFrame.style.display = "flex";
});

closeAbout.addEventListener('click', function() {
    aboutFrame.style.display = "none";
});