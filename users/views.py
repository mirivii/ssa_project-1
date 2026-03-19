import secrets, requests
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import UserRegistrationForm, EmailAuthenticationForm, TopUpForm
from .models import Transaction


RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"

def _hp_name(request):
    # stable per-session honeypot name to defeat autofill/scripts
    if "hp_name" not in request.session:
        request.session["hp_name"] = f"hp_{secrets.token_hex(8)}"
    return request.session["hp_name"]

def login_view(request):
    hp_name = _hp_name(request)

    if request.method == "POST":
        # 1) Honeypot (cheap check first)
        if request.POST.get(hp_name):
            messages.error(request, "Bot detected.")
            return redirect("users:login")

        # 2) Timing guard (humans rarely submit under 1.5s)
        try:
            elapsed = float(request.POST.get("elapsed", 0))
            if elapsed < 1.5:
                messages.error(request, "Please wait a moment before submitting.")
                return redirect("users:login")
        except (TypeError, ValueError):
            pass

        # 4) Authenticate
        username = (request.POST.get("username") or "").strip().lower()
        password = request.POST.get("password") or ""
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # rotate honeypot name after each successful POST
            request.session["hp_name"] = f"hp_{secrets.token_hex(8)}"
            next_url = request.GET.get("next", reverse("chipin:home"))
            return redirect(next_url)
        else:
            messages.error(request, "Invalid username or password.")
            return redirect("users:login")

    # GET: render with the current hp_name
    next_url = request.GET.get("next", "")
    return render(request, "users/login.html", {"hp_name": hp_name, "next": next_url})

def register(request):
    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your account has been created! You can now log in.")
            return redirect('users:login')
    else:
        form = UserRegistrationForm()
    return render(request, 'users/register.html', {'form': form})

@login_required(login_url='users:login')
def user(request):
    return render(request, "chipin/home.html")

def logout_view(request):
    logout(request)
    messages.success(request, "Successfully logged out.")
    return redirect('users:login')

@login_required(login_url='users:login')
def top_up(request):
    if request.method == 'POST': # This is the POST request (member clicks the sumbit button on the form)
        form= TopUpForm(request.POST)

        if form.is_valid():
            amount = form.cleaned_data['amount'] # retrieves the sanitised input, ensuring it's safe to use.
            profile = request.user.profile # object provides access to the logged-in user's profile.
            profile.balance += amount # the balance attribute is updated by adding the validated amount.
            profile.save()
            Transaction.objects.create(user=request.user, amount=amount) # Each top up should generate a corresponding Transaction record to maintain a history of the user's payment activity.
            messages.success(request, f"Balance has been topped up by ${amount}.")
            return redirect('chipin:home') 
    
    else: # This is the GET request (member clicks the Top Up link)
        form = TopUpForm() # Create a blank form
    return render(request, 'users/top_up.html', {'form': form}) # Send the blank form to the template
