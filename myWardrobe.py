from flask import Flask, render_template, request, redirect, \
    jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc, or_
from sqlalchemy.orm import sessionmaker
from database_setup import Base, ClothesType, ClothingItem, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# Connect to Database and create database session
engine = create_engine('sqlite:///wardrobe.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

clothing_types = session.query(ClothesType).order_by(asc(ClothesType.name))


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    if len(data['name']) == 0:
        login_session['username'] = 'User'
    else:
        login_session['username'] = data['name']
    login_session['provider'] = 'google'
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; '
    output += 'height:300px;border-radius: 150px;-webkit-border-radius:150px;'
    output += '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s - %s"
          % (login_session['username'], login_session['email']))
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user
    

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/oauth/access_token?grant_type='
           'fb_exchange_token&client_id=%s&client_secret=%s&'
           'fb_exchange_token=%s' % (app_id, app_secret, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange
        we have to split the token first on commas and select the first index
        which gives us the key: value for the server access token then we split
        it on colons to pull out the actual token value and replace the
        remaining quotes with nothing so that it can be used directly in
        the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = ('https://graph.facebook.com/v2.8/me?access_token=%s&fields='
           'name,id,email' % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = ('https://graph.facebook.com/v2.8/me/picture?access_token='
           '%s&redirect=0&height=200&width=200' % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: '
    output += '150px;-webkit-border-radius: 150px;-moz-border-radius: '
    output += '150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?access_token='
           '%s' % (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# DISCONNECT - Revoke a current user's token and reset their login_session for custom users
@app.route('/cdisconnect')
def cdisconnect():

    # Reset the user's sesson.
    del login_session['username']
    del login_session['email']
    del login_session['picture']

    response = make_response(json.dumps('Successfully disconnected.'), 200)
    response.headers['Content-Type'] = 'application/json'
    return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()

        if login_session['provider'] == 'facebook':
            fbdisconnect()

        if login_session['provider'] == 'custom':
            cdisconnect()

        flash("You have successfully been logged out.")
        return redirect(url_for('showWardrobe'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showWardrobe'))


# JSON APIs to view clothing Information
@app.route('/mywardrobe/<int:clothes_type_id>/JSON')
def clothingTypesJSON(clothes_type_id):
    items = session.query(ClothingItem).filter_by(
        type_id=clothes_type_id).all()
    return jsonify(ClothingItem=[i.serialize for i in items])


@app.route('/mywardrobe/<int:clothes_type_id>/<int:clothing_item_id>'
           '/JSON')
def clothingDetailsJSON(clothes_type_id, clothing_item_id):
    clothing_details = (
        session.query(
            ClothingItem
        )
        .filter_by(id=clothing_item_id)
        .one()
    )
    return jsonify(clothing_details=clothing_details.serialize)


@app.route('/mywardrobe/JSON')
def myWardrobeJSON():
    clothesTypes = session.query(ClothesType).all()
    items = session.query(ClothingItem).all()
    return jsonify(clothesTypes=[c.serialize for c in clothesTypes])


# Show all clothing categories and the 10 latest items
@app.route('/')
@app.route('/mywardrobe/')
def showWardrobe():
    users = session.query(User).all()
    latest_ten = (
        session.query(
            ClothingItem
        )
        .order_by(desc(ClothingItem.id))
        .limit(10)
    )
    return (render_template('latestten.html', clothing_types=clothing_types,
            latest_ten=latest_ten, users=users))


#@app.route('/register', methods = ['POST'])
#def new_user():
#    username = request.json.get('username')
#    password = request.json.get('password')
#    if username is None or password is None:
#        abort(400) # missing arguments
#    if session.query(Password).filter_by(username = username).first() is not None:
#        abort(400) # existing user
#    user = Password(username = username)
#    user.hash_password(password)
#    session.add(user)
#    session.commit()
#    return jsonify({ 'username': user.username }), 201, {'Location': url_for('get_user', id = user.id, _external = True)}

# Create a new user
@app.route('/register', methods=['GET', 'POST'])
def newUser():
    if request.method == 'POST':
        login_session['username'] = request.form['username']
        login_session['provider'] = 'custom'
        login_session['picture'] = request.form['picture']
        login_session['email'] = request.form['email']

        # See if a user exists, if it doesn't make a new one
        user_id = getUserID(login_session['email'])
        if not user_id:
            user_id = createUser(login_session)
        login_session['user_id'] = user_id

        output = ''
        output += '<h1>Welcome, '
        output += login_session['username']

        output += '!</h1>'
        output += '<img src="'
        output += login_session['picture']
        output += ' " style = "width: 300px; height: 300px;border-radius: '
        output += '150px;-webkit-border-radius: 150px;-moz-border-radius: '
        output += '150px;"> '

        flash("Now logged in as %s" % login_session['username'])
        return output
    else:
        return render_template('register.html',
                               clothing_types=clothing_types)


# Log in as user
@app.route('/userlogin', methods=['GET', 'POST'])
def userLogin():
    if request.method == 'POST':
        login_session['email'] = request.form['email']
        login_session['password'] = request.form['password']
        user_id = getUserID(login_session['email'])
        
        if not user_id:
            output = 'Please create a new user'
            return output
        else:
            user = getUserInfo(user_id)
            login_session['user_id'] = user.id
            login_session['username'] = user.name
            login_session['provider'] = 'custom'
            login_session['picture'] = user.picture
            login_session['email'] = request.form['email']

            output = ''
            output += '<h1>Welcome, '
            output += login_session['username']

            output += '!</h1>'
            output += '<img src="'
            output += login_session['picture']
            output += ' " style = "width: 300px; height: 300px;border-radius: '
            output += '150px;-webkit-border-radius: 150px;-moz-border-radius: '
            output += '150px;"> '

            flash("Now logged in as %s" % login_session['username'])
            return output
    else:
        return (render_template('userlogin.html', clothing_types=clothing_types))


# Show all items of a clothing type
@app.route('/mywardrobe/<string:clothing_type>')
def showClothing(clothing_type):
    clothes_type = (
        session.query(
            ClothesType
        )
        .filter_by(name=clothing_type)
        .one()
    )
    items = (
        session.query(
            ClothingItem
        )
        .filter_by(type_id=clothes_type.id)
        .all()
    )
    return (render_template('clothes.html', items=items,
            clothing_type=clothes_type, clothing_types=clothing_types))


# Show details of a clothing item
@app.route('/mywardrobe/<string:clothing_type>/<int:clothing_id>')
def showDetail(clothing_type, clothing_id):
    clothes_type = (
        session.query(
            ClothesType
        )
        .filter_by(name=clothing_type)
        .one()
    )
    item = session.query(ClothingItem).filter_by(id=clothing_id).one()
    user = session.query(User).filter_by(id=item.user_id).first()
    return (render_template('details.html', item=item,
            clothing_type=clothes_type, clothing_types=clothing_types,
            user=user))


# Add a new clothing item
@app.route('/mywardrobe/add', methods=['GET', 'POST'])
def addClothing():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        loggedUser = (
            session.query(
                User
            )
            .filter_by(email=login_session['email'])
            .one()
        )
        clothesType = (
            session.query(
                ClothesType
            )
            .filter_by(name=request.form['type'])
            .one()
        )
        newClothing = ClothingItem(
            name=request.form['name'],
            description=request.form['description'],
            clothesType=clothesType,
            user_id=loggedUser.id)
        session.add(newClothing)
        session.commit()
        flash("New Clothing '%s' Item Successfully Created"
              % (newClothing.name))
        return redirect(url_for('showClothing',
                                clothing_type=clothesType.name))
    else:
        return render_template('addclothing.html',
                               clothing_types=clothing_types)


# Edit a clothing item
@app.route('/mywardrobe/<string:clothing_type>/<int:clothing_id>/edit',
           methods=['GET', 'POST'])
def editClothing(clothing_type, clothing_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(ClothingItem).filter_by(id=clothing_id).one()
    clothesType = (
        session.query(
            ClothesType
        )
        .filter_by(name=clothing_type)
        .one()
    )
    if login_session['user_id'] != editedItem.user_id:
        flash("'You do not have authorization to edit '%s'" 
              % (editedItem.name))
        return redirect('/')
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['type']:
            clothesType = (
                session.query(
                    ClothesType
                )
                .filter_by(name=request.form['type'])
                .one()
            )
            editedItem.clothesType = clothesType
        session.add(editedItem)
        flash("'%s' Change successful" % (editedItem.name))
        session.commit()
        return redirect(url_for('showWardrobe'))
    else:
        return (render_template('editclothing.html', clothes_type=clothesType,
                item=editedItem, clothing_types=clothing_types))


# Delete a clothing item
@app.route('/mywardrobe/<string:clothing_type>/<int:clothing_id>/remove',
           methods=['GET', 'POST'])
def deleteClothing(clothing_type, clothing_id):
    if 'username' not in login_session:
        return redirect('/login')
    clothesType = (
        session.query(
            ClothesType
        )
        .filter_by(name=clothing_type)
        .one()
    )
    clothingToDelete = session.query(
        ClothingItem).filter_by(id=clothing_id).one()
    if login_session['user_id'] != clothingToDelete.user_id:
        flash("'You do not have authorization to delete '%s'" 
              % (clothingToDelete.name))
        return redirect('/')
    if request.method == 'POST':
        session.delete(clothingToDelete)
        flash('%s Successfully Deleted' % clothingToDelete.name)
        session.commit()
        return redirect(url_for('showClothing', clothing_type=clothing_type))
    else:
        return (render_template('deleteclothing.html',
                clothing_type=clothesType, item=clothingToDelete,
                clothing_types=clothing_types))

#session.query(Object).filter(Object.column.like('something%'))
@app.route('/mywardrobe/search', methods=['GET', 'POST'])
def searchClothing():
    if request.method == 'POST':
        query = request.form['searchrequest']
        results = (
            session.query(
                ClothingItem
            )
            .filter(or_(ClothingItem.name.contains(query),
                    ClothingItem.description.contains(query)))
            .all()
        )

        return render_template('search.html',
                               clothing_types=clothing_types, results=results) 
    else:
        return render_template('search.html',
                               clothing_types=clothing_types, results='No search results') 

if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'super_secret_key'
    app.run(host='0.0.0.0', port=8000)
