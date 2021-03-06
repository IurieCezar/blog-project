# Multi-User Blog

A multi-user blog developed using Webapp2, Jinja2 and Google App Engine. Users can sign in and post blog posts as
well as 'Like' and 'Comment' on other posts.

<img width="1420" alt="blog" src="https://cloud.githubusercontent.com/assets/19762832/26764989/9f8458a6-4937-11e7-8ec4-a67268f9ede3.png">

## Complete URL

[https://blogbyiurie.appspot.com/blog](https://blogbyiurie.appspot.com/blog)

## Getting Started
### Prerequisites
To run the project locally and to deploy it you will need to download and
install [Google App Engine SDK](https://cloud.google.com/appengine/docs/standard/python/download)

### How to run the project
* Clone the repository to your local machine:
`git clone https://github.com/iuriepopovici/blog-project`
* Navigate to the directory that contains the code:
`cd blog-project`
* From within the project directory, start the local development server with the following command:
`dev_appserver.py app.yaml`
* Visit [http://localhost:8080/](http://localhost:8080/) in your web browser to view the app.

### Make a change
You can leave the development server running while you change the application. The development server watches for changes
in your source files and reloads them if necessary. Reload [http://localhost:8080/](http://localhost:8080/) to see the results.

## Deployment

To deploy the app to App Engine you will need to:
* [Create a google account](https://accounts.google.com/SignUp?hl=en)
* [Create a project](https://cloud.google.com/appengine/docs/standard/python/console/#create)
* [Create an App Engine application](https://cloud.google.com/appengine/docs/standard/python/console/#create)
* Run the `gcloud app deploy app.yaml` command from within the root directory of your application where the configuration files(app.yaml, index.yaml) are located.

### Optional flags:
* Include the `--project` flag to specify an alternate Cloud Platform project ID to what you initialized as the default in the gcloud tool. Example: `--project [YOUR_PROJECT_ID]`
* Include the -v flag to specify a version ID, otherwise one is generated for you. Example: -v [YOUR_VERSION_ID]

## Built With

* [Webapp2](https://webapp2.readthedocs.io/en/latest/) - The web framework used
* [Jinja2](http://jinja.pocoo.org/) - Template Engine for Python
* [Google App Engine](https://cloud.google.com/appengine/)

## Authors

* **Iurie Popovici**  - *Initial work* - 
