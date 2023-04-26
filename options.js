// document.addEventListener('DOMContentLoaded', function() {
//     // var iframe = document.getElementById('my-iframe');
//     // var localServerUrl = 'http://127.0.0.1:5000'; // Replace with your local server URL
//     // iframe.src = chrome.runtime.getURL('index.html') + '?url=' + encodeURIComponent(localServerUrl);
//     // iframe.src=localServerUrl;
//     chrome.tabs.query({active: true, lastFocusedWindow: true}, tabs => {
//         let url = tabs[0].url;
//         console.log(url);
//         var iframe = document.getElementById('my-iframe');
        
//         let input_url=iframe.contentWindow.document.getElementById('url');
//         let btn=iframe.contentWindow.document.getElementById('btn');
//         input_url.innerHTML=url;
//         btn.click();
//         // use `url` here inside the callback because it's asynchronous!
//     });
//   });
  

//   window.addEventListener('message', function(event) {
//     // if (event.origin !== 'https://example.com') return;
  
//     if (event.data.type === 'element-id') {
//       var id = event.data.data;
//       console.log('ID of element: ' + id);

//     }
//   });
// console.log("running")
  
// fetch('http://127.0.0.1:5000')
//   .then(response => response.text())
//   .then(data => console.log(data))
//   .catch(error => console.error(error));