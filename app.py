from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
import pickle
warnings.filterwarnings('ignore')
from features import FeatureExtraction

file = open("model_save_new.pkl","rb")
model = pickle.load(file)
file.close()


app = Flask(__name__)

@app.route('/')
def home():
    return render_template('phising.html')


@app.route('/about')
def about():
    return render_template('about.html')
# @app.route('/url')
# def urlpage():
#     return render_template('index.html')


@app.route("/url", methods=["GET", "POST"])
def index():
    if request.method == "POST":

        url = request.form["url"]
        print(url)
        # print(url)
        obj = FeatureExtraction(url)
        # print("Feature extraction", obj)
        x = np.array(obj.getFeaturesList()).reshape(1,30) 

        y_pred =model.predict(x)[0]
        # print(y_pred)
        #1 is safe       
        #-1 is unsafe
        y_pro_phishing = model.predict_proba(x)[0,0]
        y_pro_non_phishing = model.predict_proba(x)[0,1]
        # if(y_pred ==1 ):
        pred = "It is {0:.2f}% safe to go ".format(y_pro_phishing*100)
        return render_template('index.html',xx =round(y_pro_non_phishing,2),url=url )
    return render_template("index.html", xx =-1)


@app.route('/email')
def page():
    return render_template('email.html')


@app.route('/predict', methods=['POST'])
def predict():
    print("predicted")
    df = pd.read_csv("spam_ham_dataset.csv", encoding="latin-1")
    # df.drop(['Unnamed: 2', 'Unnamed: 3', 'Unnamed: 4'], axis=1, inplace=True)
    # Features and Labels
    df['detect'] = df['label'].map({'ham': 0, 'spam': 1})
    X = df['text']
    y = df['detect']
    # Extract Feature With CountVectorizer
    cv = CountVectorizer()
    X = cv.fit_transform(X)  # Fit the Data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=42)
    # Naive Bayes Classifier
    clf = MultinomialNB()
    clf.fit(X_train, y_train)
    clf.score(X_test, y_test)
    if request.method == 'POST':
        text = request.form['textinput']
        data = [text]
        vect = cv.transform(data).toarray()
        my_prediction = clf.predict(vect)
    return render_template('email.html', prediction=my_prediction)

if __name__ == "__main__":
    app.run(debug=True)