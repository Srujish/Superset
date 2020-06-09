from flask import redirect, g, flash, request, session, current_app, url_for, make_response
from flask_appbuilder.security.views import UserDBModelView, AuthDBView,AuthLDAPView,AuthView,AuthOIDView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user
from flask_appbuilder.security.forms import LoginForm_db
from urllib.parse import quote
from superset import app
import requests

#config = app.config
#sso_app_host = config["SSO_HOST"]
#sso_app_port = config["SSO_PORT"] 
#sso_app_name = config["SSO_NAME"]

class SSOSessionClient:
    def __init__(self, sso_app_host, sso_app_port, sso_app_name):
        self.sso_app_host = sso_app_host
        self.sso_app_port = sso_app_port
        self.sso_app_name = sso_app_name

    def get_sso_session_app_url(self):
        return 'http://' + self.sso_app_host + ':' + str(self.sso_app_port) + '/' + self.sso_app_name

    def create_sso_session(self, app_name, username):
        try: 
            files = {'applicationName': app_name, 'username': username}
            response = requests.post(self.get_sso_session_app_url(), files=files)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return str(e)

    def get_sso_session(self, sso_session_id):
        try:
            response = requests.get(self.get_sso_session_app_url() + '/' + sso_session_id)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return str(e)

    def delete_sso_session(self, sso_session_id):
        try:
            response = requests.delete(self.get_sso_session_app_url() + '/' + sso_session_id)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return str(e)


class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'


    @expose('/login/', methods=['GET', 'POST'])
    def login(self):

        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        form = LoginForm_db()
        if form.validate_on_submit():
            user = self.appbuilder.sm.auth_user_db(
                form.username.data, form.password.data
            )
            if not user:
                flash(as_unicode(self.invalid_login_message), "warning")
                return redirect(self.appbuilder.get_url_for_login)
            login_user(user, remember=False)

            response = make_response(redirect(self.appbuilder.get_url_for_index))
            client = SSOSessionClient('34.212.135.8', 1978, 'ssosession')
            postResponse = client.create_sso_session('SUPERSET', user.username )
            cook = postResponse['id']
            #cook = user.username +':'+ form.password.data


            if response is not None:
                #response.set_cookie('sso', value=cook )
                response.set_cookie('sso', value=cook , domain = '.qubz-bi.com' )
                return response 

            return redirect(self.appbuilder.get_url_for_index)

        return self.render_template(
            self.login_template, title=self.title, form=form, appbuilder=self.appbuilder
        )

    @expose("/logout/")
    def logout(self):
        name = request.cookies.get('sso')
        logout_user()
        client = SSOSessionClient('34.212.135.8', 1978, 'ssosession')
        client.delete_sso_session(name)
        return redirect(self.appbuilder.get_url_for_index)

class CustomSecurityManager(SupersetSecurityManager):
    authldapview = CustomAuthDBView
    #authdbview  = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)