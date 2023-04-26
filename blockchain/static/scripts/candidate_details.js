$(document).ready(function(){
    $('#vote-now').click(function(event){

        show_loading('Please wait, Private Key is being sent your email-id.');

        $.ajax(
            {
                type:'GET',
                url: '/get-parties/',
                data: 'None',
                success: function(data){

                    parties_list_json = data.parties;
                    $('.main-content').html(data.html);

                    hide_loading();

                    showAlert('Make your choice. Remember you are going to select a new Representative.', 'rgba(201, 136, 255, 0.3)', 'rgb(102, 0, 128)');
                }
            }
        );
    });

});