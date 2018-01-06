## My Wardrobe App - Synopsis

'My Wardrobe' is a basic catalog application that allows registered users to add, edit, and delete their clothing items within organized clothing categories.


## Installation

Before you run this program, you will require a Virtual Machine to run the web server and a web app that uses it. You can download the following programs below: 

[Virtual Box](https://www.virtualbox.org/wiki/Downloads)
[Vagrant](https://www.vagrantup.com/downloads)
Download my_wardrobe.zip

#### Required Files

Once you set up your virtual machine and log your terminal in, change your directory to the My Wardrobe folder and ensure you have the following:

* myWardrobe.py
* database_setup.py
* lotsofclothes.py
* 'static' directory
* 'templates' directory

#### Running the My Wardrobe App

1. Initialize the database

```
python database_setup.py
```

2. Populate the database with clothing catagories and sample clothing

```
python lotsofclothes.py
```

3. Run the flask web server

```
python myWardrobe.py
```

4. Open your web browser

Visit http://localhost:8000 to view the clothing catalog. If logged in, you will be able to add, edit, and delete items.

## Motivation

This mini project was created for [Udacity](https://www.udacity.com/) and submitted for the **Full Stack Web Developer Nanodegree** program. 

## Supported Python Versions

My Wardrobe is supported by Python 2.7.9 [MSC v.1500 32 bit (Intel)] on win32

## Contributors

Jennifer Nguyen  
Udacity  [[Website]](https://www.udacity.com/)  
Le Chateau (descriptions for sample clothing)  [[Website]](https://www.lechateau.com/)

## License

My Wardrobe is an open source project and may be redistributed under the terms specified in the LICENSE file.