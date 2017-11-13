from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem



from flask import session as login_session
import random
import string

# creates a flow object from the clientssecrets JSON file
# This JSON formatted style stores your client ID, client secret and other OAuth 2.0 parameters.
from oauth2client.client import flow_from_clientsecrets
## this FlowExchangeError method will be used if get an error trying to exchange an
## authorization code for an access token. This method will catch itself.
from oauth2client.client import FlowExchangeError
import httplib2
#The JSON module provides an API for converting in memory Python objects to a
#serialized representation, know as JSON, or Java Script Object Notation.
import json
#The make_response method converts the return value from a function into a real make_response
#object that we can send off to our client.
from flask import make_response
#requests is an Apache 2.0 licensed HTTP library written in Python similar to urllib2,
#, but with a few improvements
import requests

app = Flask(__name__)

#clientID will reference client_secrets.json file
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"



#Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


## new routhing path called login
@app.route('/login')
## create a showLogin function that creates a state variable.
## state will be 32 characters long and contains a mix of upperscase leters and
## digits.
def showLogin():
    ##anti forgery token 32 char long
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    ## we store state in our login_session object ander the name state look 'state'
    login_session['state'] = state
## RENDER THE LOGIN TEMPLATE
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # confirm that the token that the client sends to the server matches the token
    # that the server sent to the client. This round trip verification helps ensure that
    # the user is making the request and not a malicious script
    if request.args.get('state') != login_session['state']:
        # using the request.args.get method, my code examines the state token
        #passed in and compares it to the state of the login session. If these two do
        #not match , then i create a response of an ivalid state token and
        #return this message to the client. No further authentication will occur on the
        #server side if there's mismatch. between these state tokens
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # collect the one time code from my server with the request.data function.
    code = request.data

    #Next i will try and use this one time code and exchange it for a credentials
    #object which will contain the access token for my server.
    try:
        # a credentials object which will contain the access token for my server.
        # This line creates an oauth flow object and adds my client's secret key information to it.
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        #here i specify with post message that this is the one time code flow
        # my server will be sending off.
        oauth_flow.redirect_uri = 'postmessage'
        ## initiate the exchange with the step two exchange function, passing
        # in my one-time code as input. This step to exchange function of the flow class
        #exchanges an authorization code for a credentials object.
        # If all goes well, then the response from Goolge will be an objects
        #I am storing under the name credentials
        credentials = oauth_flow.step2_exchange(code)
    # If an error happens along the way, then i will throw this flow exchange FlowExchangeError
    # and send the response as JSON object.
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Now that I have this credentials object,i will check and see if there's a ivalid
    # access token inside of it.
    # If there was an error in the access token info, abort.

    # i will store credentials.access_token in a variable called stored_access_token
    access_token = credentials.access_token
    # append this token to the following Google URL, the Google API server can
    # verify that this is a valid token for use.
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # In these two lines of code, i create a json GET request containing the URL and
    # access token..Store the result of this request in a variable called result.
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # if my result contains any errors, then i send the 500 Internal Server Error to my client.
    if result.get('error') is not None:
        # if this statment is not true that we know that we have a working access token
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # But now let's make sure that we have the right access token.
    gplus_id = credentials.id_token['sub'] # grab the ID of the token in my credentials object
    # compare it to the ID returned by the Google API server. If these two ID's do not match the i do not have the correct token
    # and should return an error.
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # ## similarly if the client IDs do not match my app is trying to use a client ID
    ## that does not belong to it so i shouldn't allow for this.
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
# check to see if user is alread logged in. This will return a 200 Successful
# authentication without resetting all of the login session variables again.
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # in none of these if statments were true, we have a valid access token.
    # and user is successfully able to login into my server
    # In this users's login session i will sotre their credentials in Google Plus ID.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    #using Google Plus API get some more information aout user
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    #send a message to the Google API server with my access token requesting the user info
    # allowed by my token scope and stored in an object i will call data
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    # store the user datathat we are interested
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # if everything worked then we should be able to create a response that knows the user's
    #name and can return their picture
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    # flas message to let the user know that they are logged in.
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
  restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
  return render_template('restaurants.html', restaurants = restaurants)

#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
  if request.method == 'POST':
      newRestaurant = Restaurant(name = request.form['name'])
      session.add(newRestaurant)
      flash('New Restaurant %s Successfully Created' % newRestaurant.name)
      session.commit()
      return redirect(url_for('showRestaurants'))
  else:
      return render_template('newRestaurant.html')

#Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
  editedRestaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if request.method == 'POST':
      if request.form['name']:
        editedRestaurant.name = request.form['name']
        flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
        return redirect(url_for('showRestaurants'))
  else:
    return render_template('editRestaurant.html', restaurant = editedRestaurant)


#Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
  restaurantToDelete = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if request.method == 'POST':
    session.delete(restaurantToDelete)
    flash('%s Successfully Deleted' % restaurantToDelete.name)
    session.commit()
    return redirect(url_for('showRestaurants', restaurant_id = restaurant_id))
  else:
    return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)

#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
    return render_template('menu.html', items = items, restaurant = restaurant)



#Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if request.method == 'POST':
      newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], course = request.form['course'], restaurant_id = restaurant_id)
      session.add(newItem)
      session.commit()
      flash('New Menu %s Item Successfully Created' % (newItem.name))
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
      return render_template('newmenuitem.html', restaurant_id = restaurant_id)

#Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):

    editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)


#Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id = restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item = itemToDelete)




if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
