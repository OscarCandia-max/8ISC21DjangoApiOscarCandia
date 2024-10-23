from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

# login view
def login_view(request):
    template_name = "auth-login.html"
    if request.user.is_authenticated:
        return redirect('home')  
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
    
        # Intenta autenticar al usuario
        
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            # Puedes buscar si el usuario existe por correo electrónico
            try:
                user = User.objects.get(email=username)
                # Si el usuario existe, verifica la contraseña
                if user.check_password(password):
                    login(request, user)
                    return redirect('home')
            except User.DoesNotExist:
                pass
            
            return render(request, template_name, {'error': 'Credenciales invalidas'})

    return render(request, template_name)
#verifica si el usuario ya esta autenticado 




# register view
def register_view(request):
    template_name = "auth-register.html"
    return render(request,template_name)
# forgot the password view
def forgot_view(request):
    template_name = "auth-forgot-password.html"
    return render(request,template_name)

def indexrent_view(request):
    template_name = "indexrent.html"
    return render(request,template_name)
#view for logout
def logout_view(request):
    logout(request)
    return redirect('login_vista')