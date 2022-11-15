from flask import Blueprint, render_template, request, flash, redirect, session, url_for
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db

auth = Blueprint("auth", __name__)

@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logado com sucesso!", category="success")
                login_user(user, remember=True)
                return redirect(url_for("views.video"))
            else:
                flash("Senha incorreta!", category="error")
        else:
            flash("Email não existe nos registros.", category="error")

    return render_template("login.html", user=current_user)

@auth.route("/logout")
@login_required
def logout():
    session.clear()
    logout_user()
    flash("Deslogado com sucesso!", category="success")
    return redirect(url_for("views.video"))

@auth.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get("name")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user = User.query.filter_by(email=email).first()
        if user:
            flash("Este user já está cadastrado", category="error")
        elif len(email) < 4:
            flash("Email não é válido", category="error")
        elif len(name) < 2:
            flash("O nome é inválido. Deve conter pelo menos 2 caracteres.", category="error")
        elif password1 != password2:
            flash("A senha não bateu.", category="error")
        elif len(password1) < 6:
            flash("Senha é inválida, deve conter pelo menos 6 caracteres.", category="error")
        else:
            new_user = User(email=email, name=name, password=generate_password_hash(password1, method="sha256"))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash("Conta criada, redirecionando.", category="success")
            return redirect(url_for("views.video"))

    return render_template("sign_up.html", user=current_user)

@auth.route("/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():
    if request.method == "POST":
        confirm_message = request.form.get("confirm-message")
        if confirm_message != "delete-account":
            flash("Mensagem de confirmação incorreta!", category="error")
            return render_template("delete_account.html", user=current_user) 

        try:
            db.session.delete(current_user)
            db.session.commit()
            logout_user()
            flash("Conta deletada dos regristros.", category="success")
            return redirect(url_for("views.video"))
        except Exception:
            flash("Não foi possível excluir a conta.", category="error")
    return render_template("delete_account.html", user=current_user)