# Multi User Blog
A multi-user blog developed using Google App Engine.

## Complete URL

[https://blogbyiurie.appspot.com/blog](https://blogbyiurie.appspot.com/blog)

## Getting Started
### Prerequisites
To run the project locally and to deploy it you will need to download and
install [Google App Engine SDK](https://cloud.google.com/appengine/docs/standard/python/download)

### How to run the project
* Clone the repository to your local machine:
`git clone https://github.com/IurieCezar/blog-project`
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
* [An App Engine application](https://cloud.google.com/appengine/docs/standard/python/console/#create)
* Run the `gcloud app deploy app.yaml` command from within the root directory of your application where the configuration files(app.yaml, index.yaml) are located.

###Optional flags:
* Include the `--project` flag to specify an alternate Cloud Platform project ID to what you initialized as the default in the gcloud tool. Example: `--project [YOUR_PROJECT_ID]`
* Include the -v flag to specify a version ID, otherwise one is generated for you. Example: -v [YOUR_VERSION_ID]

## Built With

* [Webapp2](https://webapp2.readthedocs.io/en/latest/) - The web framework used
* [Jinja2](http://jinja.pocoo.org/) - Template Engine for python
* [Google App Engine](https://cloud.google.com/appengine/)

## Authors

* **Iurie Popovici**  - *Initial work* - 
