/*document.getElementById('logout-button').addEventListener('click', function(){
    Swal.fire({
        title: '¿Estás seguro?',
        text: 'Perderas tu sesion actual',
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor : '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText : 'Si',
        cancelButtonText: 'No'

    }).then((result)=> {
        if(result.isConfirmed){
            window.location.href = '{% url 'logout' %}';
        }
    });
});