from flask import redirect, g, flash, request, session, current_app, url_for, make_response
from flask_appbuilder.security.views import UserDBModelView, AuthDBView,AuthLDAPView,AuthView,AuthOIDView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user
from flask_appbuilder.security.forms import LoginForm_db
from urllib.parse import quote


class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'


    @expose('/login/', methods=['GET', 'POST'])
    def login(self):

        name = request.cookies.get('sso')

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
            cook = user.username +':'+ form.password.data


            if response is not None:
                #response.set_cookie('sso', value=cook )
                response.set_cookie('sso', value=cook , domain = '.qubz-bi.com' )
                return response 

            return redirect(self.appbuilder.get_url_for_index)

           
        #response = make_response(redirect(self.appbuilder.get_url_for_index))
        #if response is not None:
            #return response.set_cookie('sso', user)
            #name = request.cookies.get('sso')

        return self.render_template(
            self.login_template, title=self.title, form=form, appbuilder=self.appbuilder
        )

class CustomSecurityManager(SupersetSecurityManager):
    authldapview = CustomAuthDBView
    #authdbview  = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)