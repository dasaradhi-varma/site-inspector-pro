// background.js — Service Worker for Site Inspector

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getTabInfo") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        sendResponse({ url: tabs[0].url, title: tabs[0].title });
      }
    });
    return true;
  }
});
