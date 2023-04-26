$(document).ready(function(){
    hide_loading();
    showAlert(
        'Enter The Private Key Here',
        'rgba(201, 136, 255, 0.3)', 'rgb(102, 0, 128)');
    setTimeout(function(){
        $('.loading-div').css({
            'height': 'calc(100vh - 50px)',
            'top': '50px',
        });
    }, 1000);
})