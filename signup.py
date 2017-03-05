'''Multi-user blog web-application, written by Iurie Popovici using webapp2
Python web framework and Jinja2 templating language.'''

import os
import jinja2
import webapp2
import re
import hashlib
import hmac
import random
import string
import time
from google.appengine.ext import db


# Create Jinja environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'udacity_is_great!!!'


# Password hashing functions:
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, password, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + password + salt).hexdigest()
    return "%s,%s" % (h, salt)


def valid_pw(name, password, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, password, salt)


# Cookie hashing functions:
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# Regex functions:
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASSWORD_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASSWORD_RE.match(password)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Handler(webapp2.RequestHandler):
    '''
    Inherits from webapp2.RequestHandler, provides helper methods
    for other handlers that inherit from Handler.
    '''
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Set a session cookie using hashing functions
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Get the cookie from the request
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Set the cookie using user_id
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Delete the cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Checks to see if the user is logged in(on every page)
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def check_if_valid_post(self, post_id):
        key = db.Key.from_path("Blog", int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            return self.redirect("/blog/login")

    def check_if_valid_comment(self, com_id):
        key = db.Key.from_path("Comment", int(com_id), parent=comment_key())
        comment = db.get(key)
        if not comment:
            return self.redirect("/blog/login")

    def user_owns_post(self, post_id):
        key = db.Key.from_path("Blog", int(post_id), parent=blog_key())
        post = db.get(key)
        return self.user.username == post.author

    def user_owns_comment(self, com_id):
        key = db.Key.from_path("Comment", int(com_id), parent=comment_key())
        comment = db.get(key)
        return self.user.username == comment.commenter


# User parent
def users_key(group='default'):
    return db.Key.from_path('users', group)


# Entity kinds in the datastore
class User(db.Model):
    '''Columns in User entity'''
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def register(cls, username, password, email=None):
        pw_hash = make_pw_hash(username, password)
        return User(parent=users_key(),
                    username=username,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())


# Blog parent
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Blog will be the name of the entity kind
class Blog(db.Model):
    subject = db.StringProperty()
    content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty()
    liked_by = db.ListProperty(str, default=None)
    likes = db.IntegerProperty(required=True, default=0)

    def render_comments(self):
        comments = db.GqlQuery("select * from Comment order by created desc")
        seq = []
        for comment in comments:
            if(comment.post_id == self.key().id()):
                seq.append(comment)
        return seq


# Blog parent
def comment_key(name='default'):
    return db.Key.from_path('comments', name)


class Comment(db.Model):
    com_id = db.IntegerProperty()
    comment = db.TextProperty()
    post_id = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    commenter = db.StringProperty(required=True)
    commenter_id = db.IntegerProperty(required=True)


# Create account for new users
class Signup(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        user_exist = db.GqlQuery("select * from User where username=:1",
                                 username).get()

        d = dict(username=username,
                 email=email)

        if not valid_username(username):
            d.update({'username_error': "That's not a valid username."})
            have_error = True

        elif user_exist:
            d.update({'username_exist_error': "That user already exists."})
            have_error = True

        if not valid_password(password):
            d.update({'password_error': "That wasn't a valid password."})
            have_error = True

        elif password != verify:
            d.update({'verify_password_error': "Your passwords didn't match."})
            have_error = True

        if not valid_email(email):
            d.update({'email_error': "That's not a valid email."})
            have_error = True

        if have_error:
            self.render('signup.html', **d)
        else:
            a = User.register(username=username,
                              password=password,
                              email=email)
            a.put()
            self.login(a)
            self.redirect("/")


class Welcome(Handler):
    def get(self):
        if self.user:
            self.render("welcome.html", username=self.user.username)
        else:
            self.redirect("/blog/login")


class NewPost(Handler):
    def render_front(self, subject="", content="", error=""):
        contents = db.GqlQuery("select * from Blog order by created desc")

        self.render("new_post.html", subject=subject,
                    content=content,
                    error=error,
                    contents=contents)

    def get(self):
        if not self.user:
            self.redirect("/blog/login")
        else:
            self.render_front()

    def post(self):
        if not self.user:
            self.redirect("/blog/login")
        else:
            author = self.user.username
            subject = self.request.get("subject")
            content = self.request.get("content")
            # Check if the input is empty, if yes error will be displayed
            if (subject and content and
                    not (subject.isspace() or content.isspace())):
                b = Blog(parent=blog_key(),
                         subject=subject,
                         content=content,
                         author=author)
                b.put()
                post_id = b.key().id()
                self.redirect("/blog/%d" % post_id)
            else:
                error = "Error: We need both a subject, and some content!"
                self.render_front(subject, content, error)


class Single_Post(Handler):
    def get(self, post_id):
        self.check_if_valid_post(post_id)
        b = Blog.get_by_id(int(post_id), parent=blog_key())
        if not b:
            self.error(404)
            return
        comments = b.render_comments()
        self.render("single_post.html", comments=comments,
                    b=b,)


class EditPost(Handler):
    def get(self, post_id):
        self.check_if_valid_post(post_id)
        if not self.user:
            self.redirect("/blog/login")
        else:
            if self.user_owns_post(post_id):
                b = Blog.get_by_id(int(post_id), parent=blog_key())
                error = ""
                self.render("edit_post.html", b=b,
                            error=error,
                            post_id=post_id)
            else:
                not_post_owner_error = ("error: You can only edit/delete \
                                        your own posts!")
                b = Blog.get_by_id(int(post_id), parent=blog_key())
                comments = b.render_comments()
                self.render("single_post.html", comments=comments,
                            not_post_owner_error=not_post_owner_error,
                            b=b)

    def post(self, post_id):
        self.check_if_valid_post(post_id)
        if not self.user:
            self.redirect("/blog/login")
        else:
            b = Blog.get_by_id(int(post_id), parent=blog_key())
            b.subject = self.request.get("subject")
            b.content = self.request.get("content")
            # Check if the input is empty, if yes error will be displayed
            if not (b.subject and b.content and
                    not (b.subject.isspace() or b.content.isspace())):
                error = "Error: We need both a subject, and some content!"
                self.render("edit_post.html", b=b,
                                              error=error)
            else:
                b.put()
                time.sleep(0.1)
                self.redirect('/blog/%s' % str(b.key().id()))


class DeletePost(Handler):
    def get(self, post_id):
        self.check_if_valid_post(post_id)
        if not self.user:
            self.redirect("/blog/login")
        else:
            if self.user_owns_post(post_id):
                key = db.Key.from_path("Blog", int(post_id), parent=blog_key())
                content = db.get(key)
                content.delete()
                time.sleep(0.1)
                self.redirect("/blog")
            else:
                not_post_owner_error = "error: You can only edit/delete \
                                       your own posts!"
                b = Blog.get_by_id(int(post_id), parent=blog_key())
                comments = b.render_comments()
                self.render("single_post.html", comments=comments,
                            not_post_owner_error=not_post_owner_error,
                            b=b)


class HomePage(Handler):
    def get(self):
        contents = db.GqlQuery("select * from Blog order by created desc")
        comments = db.GqlQuery("select * from Comment order by created desc")
        self.render("all_posts.html", contents=contents,
                    comments=comments)


class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        user_exist = db.GqlQuery("select * from User where username=:1",
                                 username).get()
        if (user_exist and valid_pw(username, password, user_exist.pw_hash)):
            self.login(user_exist)
            self.redirect('/')
        else:
            self.render("login.html", login_error="Invalid login")


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect("/blog/login")


class Like(Handler):
    def get(self, post_id):
        if not self.user:
            self.redirect("/blog/login")
        else:
            self.check_if_valid_post(post_id)
            if self.user_owns_post(post_id):
                like_error = "error: You can not like your own posts!"
                b = Blog.get_by_id(int(post_id), parent=blog_key())
                comments = b.render_comments()
                self.render("single_post.html", comments=comments,
                            like_error=like_error,
                            b=b)
            else:
                key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
                content = db.get(key)
                current_user = self.user.username
                content.likes = content.likes + 1
                content.liked_by.append(current_user)
                content.put()
                time.sleep(0.1)
                self.redirect("/blog/%s" % post_id)


class UnLike(Handler):
    def get(self, post_id):
        self.check_if_valid_post(post_id)
        if not self.user:
            self.redirect("/blog/login")
        else:
            key = db.Key.from_path("Blog", int(post_id), parent=blog_key())
            content = db.get(key)
            author = content.author
            current_user = self.user.username
            if current_user in content.liked_by:
                content.likes = content.likes - 1
                content.liked_by.remove(current_user)
                content.put()
                time.sleep(0.1)
                self.redirect("/blog/%s" % post_id)
            else:
                self.write("You did not like this post!")


class CommentHandler(Handler):
    def post(self, post_id):
        self.check_if_valid_post(post_id)
        if not self.user:
            self.redirect("/blog/login")
        else:
            commenter_id = self.user.key().id()
            commenter = self.user.username
            comment = self.request.get("comment")
            post_id = int(post_id)
            # Check if the input is empty, if yes error will be displayed
            if not comment or comment.isspace():
                b = Blog.get_by_id(int(post_id), parent=blog_key())
                comments = b.render_comments()
                error = "error: We need some content for the comment!!!"
                self.render("single_post.html", comments=comments,
                            b=b,
                            error=error)
            else:
                c = Comment(parent=comment_key(),
                            commenter_id=commenter_id,
                            commenter=commenter,
                            post_id=post_id,
                            comment=comment)
                c.put()
                c.com_id = c.key().id()
                c.put()
                time.sleep(0.1)
                self.redirect("/blog/%s" % post_id)


class DeleteComment(Handler):
    def post(self, post_id, com_id):
        self.check_if_valid_post(post_id)
        self.check_if_valid_comment(com_id)
        if not self.user:
            self.redirect("/blog/login")
        else:
            com_id = int(com_id)
            post_id = self.request.get("post_id")

            if self.user_owns_comment(com_id):
                key = db.Key.from_path("Comment", com_id, parent=comment_key())
                comment = db.get(key)
                comment.delete()
                time.sleep(0.1)
                self.redirect(("/blog/%s" % str(post_id)))
            else:
                not_owner_error = "error: You can only edit/delete \
                                  your own comments!"
                b = Blog.get_by_id(int(post_id), parent=blog_key())
                comments = b.render_comments()
                self.render("single_post.html", comments=comments,
                            not_owner_error=not_owner_error,
                            b=b)


class EditComment(Handler):
    def get(self, post_id, com_id):
        self.check_if_valid_post(post_id)
        self.check_if_valid_comment(com_id)
        if not self.user:
            self.redirect("/blog/login")
        else:
            b = Blog.get_by_id(int(post_id), parent=blog_key())
            comment = Comment.get_by_id(int(com_id), parent=comment_key())
            if self.user_owns_comment(com_id):
                if comment:
                    error = ""
                    self.render("edit_comment.html", b=b,
                                comment=comment.comment,
                                created=comment.created,
                                error=error,
                                post_id=post_id)
                else:
                    self.redirect("/blog/%s" % str(post_id))
            else:
                comments = b.render_comments()
                not_owner_error = "error: You can only edit/delete \
                                  your own comments!"
                self.render("single_post.html", comments=comments,
                            not_owner_error=not_owner_error,
                            b=b,)

    def post(self, post_id, com_id):
        self.check_if_valid_post(post_id)
        self.check_if_valid_comment(com_id)
        comment = Comment.get_by_id(int(com_id), parent=comment_key())
        b = Blog.get_by_id(int(post_id), parent=blog_key())
        comment.comment = self.request.get("comment")
        # Check if the input is empty, if yes error will be displayed
        if not comment.comment or comment.comment.isspace():
            error = "error: We need some content for the comment!!!"
            self.render("edit_comment.html", b=b,
                        comment=comment.comment,
                        created=comment.created,
                        error=error)
        else:
            comment.put()
            time.sleep(0.1)
            self.redirect("/blog/%s" % str(post_id))

# URI routes stored by the WSGIApplication
app = webapp2.WSGIApplication([("/signup", Signup),
                               ("/blog/login", Login),
                               ("/blog", HomePage),
                               ("/blog/newpost", NewPost),
                               (r"/blog/([0-9]+)", Single_Post),
                               ("/", Welcome),
                               ("/blog/logout", Logout),
                               (r"/blog/([0-9]+)/deletepost", DeletePost),
                               (r"/blog/([0-9]+)/editpost", EditPost),
                               (r"/blog/([0-9]+)/like", Like),
                               (r"/blog/([0-9]+)/unlike", UnLike),
                               (r"/blog/([0-9]+)/comment", CommentHandler),
                               (r"/blog/([0-9]+)/deletecomment/([0-9]+)",
                                DeleteComment),
                               (r"/blog/([0-9]+)/editcomment/([0-9]+)",
                                EditComment)
                               ],
                              debug=True)
