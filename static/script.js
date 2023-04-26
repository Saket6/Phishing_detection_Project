// let x = '{{xx}}';
// let num = x*100;
// if (0<=x && x<0.50){
//     num = 100-num;
// }
// let txtx = num.toString();
// if(x<=1 && x>=0.50){
//     var label = "Website is safe to use...";
//     document.getElementById("prediction").innerHTML = label;
//     document.getElementById("button1").style.display="block";
// }
// else if (0<=x && x<0.50){
//     var label = "Website is unsafe to use..."
//     document.getElementById("prediction").innerHTML = label ;
//     document.getElementById("button2").style.display="block";
// }





console.log(13);
document.addEventListener('DOMContentLoaded', function() {
    console.log("document loaded");
    // var iframe = document.getElementById('my-iframe');
    // var localServerUrl = 'http://127.0.0.1:5000'; // Replace with your local server URL
    // iframe.src = chrome.runtime.getURL('index.html') + '?url=' + encodeURIComponent(localServerUrl);
    // iframe.src=localServerUrl;
    chrome.tabs.query({active: true, lastFocusedWindow: true}, tabs => {
        console.log("query loaded")
        let url = tabs[0].url;
        console.log(url);
        // var iframe = document.getElementById('my-iframe');
        
        let input_url=document.getElementById('url');
        // let btn=iframe.contentWindow.document.getElementById('btn');
        input_url.innerHTML=url;
        // btn.click();
        // use `url` here inside the callback because it's asynchronous!
    });
  });



