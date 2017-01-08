import os
import webapp2
import jinja2
import re
import hmac
import random
import string
import hashlib

from google.appengine.api import memcache
from google.appengine.ext import db

# get directory path to templates.
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# setup jinja_env with autoescape feature off to allow html code when editing.
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=False)

# secret string used for hashing passwords
secret = 'mysecret'


# render_str renders the template using jinja, accepts an arbitrary amount of
# parameters which will be matched with the parameters in the template.
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# make_secure_val takes in a value, val, and returns a string with the value
# and the hashed value, separated by a '|'.
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


# check_secure_val takes in a secure value, secure_val, which is the same
# format as the make_secure_val output. It returns just the value, val, if
# secure_val matches what make_secure_val outputs when it is given val.
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# class Handler will be inhereted by classes later on to handle tasks such as
# writing content, rendering pages, setting cookies, reading cookies, logging
# in, logging out, and initializing the user.
class Handler(webapp2.RequestHandler):
    # write takes in an arbitrary amount of arguments and will print them
    # out to the template. This is used by render, primarily, to write a
    # template to the page.

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # render_str takes in a template and parameters meant to be passed to the
    # template, and calls the global render_str function to render the
    # template.
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    # render will take in a template along with parameters meant to be passed
    # to the template, and writes the rendered template to the page.
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # set_secure_cookie takes in a name and a value, val, and creates a cookie
    # with the given name and a secure version of the value, with the Path set
    # to '/'.
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # read_secure_cookie takes in a name and returns whether or not the cookie
    # value is secure.
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # login handles when users log in by setting their user_id as a cookie.
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # logout clears the user_id cookie.
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # initialize will be activated by the webapp2 whenever used initially to
    # set the user_id properties.
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def logged_in(self):
        user_id = self.read_secure_cookie('user_id')
        if user_id:
            return True
        else:
            return False


user = ""


# class MainPage inherits from Handler, and when a get request is sent it will
# first try to fetch the page from cache, and if not then it will render from
# the database. This renders the main page of the wiki.
class MainPage(Handler):

    def get(self):
        global user
        logged_in = self.logged_in()
        content = memcache.get("/")
        if user == "Timr11" and content:
            self.render("mainpage.html", content=content, logged_in=logged_in,
                        username=user, edit_url="/_edit/")
        elif user == "Timr11":
            self.render("mainpage.html", content="", logged_in=logged_in,
                        username=user, edit_url="/_edit/")
        elif content:
            self.render("mainpage.html", content=content, logged_in=logged_in,
                        username=user)
        else:
            self.render("mainpage.html", content="", logged_in=logged_in,
                        username=user)


# class NewPage handels when a new page is created. It creates a new database
# entry with the content and the url.
class NewPage(db.Model):
    content = db.TextProperty(required=True)
    url = db.StringProperty(required=True)


# class WikiPage will handle when somebody enters a site that is not for
# registration, login, logout, for editing a page, or the mainpage. This will
# determine whether the site has content, and if it doesn't and the user is
# logged in then it will render the edit page, otherwise it will
class WikiPage(Handler):

    def get(self, url):
        content = memcache.get(url)
        logged_in = self.logged_in()
        if logged_in and not content:
            self.redirect('/_edit%s' % url)
        elif not content:
            content = ""

        self.render('apage_form.html', content=content, edit_url="/_edit%s"
                    % url, logged_in=logged_in, username=user)


class EditPage(Handler):

    def get(self, url):
        logged_in = self.logged_in()
        if self.logged_in():
            content = memcache.get(url)
            edit_url = "/_edit%s" % url
            if content:
                self.render("editpage.html", content=content,
                            edit_url=edit_url, logged_in=logged_in,
                            username=user)
            else:
                self.render("editpage.html", logged_in=logged_in)
        else:
            self.redirect(url)

    def post(self, url):
        content = self.request.get('content')
        if content:
            np = NewPage(content=content, url=url)
            np.put()
            memcache.set(url, content)
            self.redirect(url)
        else:
            error = "Gimme some content!"
            edit_url = "/_edit%s" % url
            self.render("editpage.html", error=error, edit_url=edit_url)


############# Signing In Functions ####################


class Signup(Handler):

    def get(self):
        self.render("registration_form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not checkUser(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not checkPass(self.password):
            params['error_password'] = "That's not a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        if not checkEmail(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('registration_form.html', **params)
        else:
            self.done()

    def done(self):
        global user
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists!'
            self.render('registration_form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            user = self.username
            self.login(u)
            self.redirect('/')


class Login(Handler):

    def get(self):
        self.render('login_form.html')

    def post(self):
        global user
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            user = username
            self.login(u)
            self.redirect('/')
        else:
            err_msg = "Invalid Login"
            self.render('login_form.html', error=err_msg)


class Logout(Handler):

    def get(self):
        global user
        user = ""
        self.logout()
        self.redirect('/')

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def checkUser(username):
    return USER_RE.match(username)


def checkPass(password):
    return PASS_RE.match(password)


def checkVer(password, verify):
    return password == verify


def checkEmail(email):
    if email:
        return EMAIL_RE.match(email)
    else:
        return True


def make_salt():
    return ''.join(random.choice(string.letters) for x in range(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, pw, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, pw, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication(
    [('/signup', Signup),
     ('/login', Login),
     ('/logout', Logout),
     ('/_edit' + PAGE_RE, EditPage),
     ('/', MainPage),
     (PAGE_RE, WikiPage)], debug=True)
