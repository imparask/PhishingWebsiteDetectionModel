# PhishingWebsiteDetectionModel

In this repository you would be able to find Feature Extraction and the final Prediction File.

# 1. Feature Extraction :
Both the feature extraction files follow the same process to classify urls based on 13 features. The only difference is FeatureExtraction.py is used for extracting features of the url you want to predict.
The other feature extraction file PhishingFeatureExtraction.py is used for creating a suitable training and testing data set for the model. The training data set is already created and stored in spiltted_data files in DATA folder.

# 2. Prediction of Url :
The checkUrl.py is the actual file where you need to enter the url and check whether its a phishing website url or a legitimate url. TensorFLow and Keras libraries would be required for creating and the training and testing the ML model.
Once the model is ready it has been stored as a Keras file in urlKeras.h5 file and then it was further converted to TensorFLow Lite model and stored in urlTflite.tflite file.

The command one needs to type in command prompt for converting keras file into tensorflowlite is toco \ --output_file=trained_model.tflite\ --keras_model_file=trained_model.h5

The application for predicting the url is available on my other repository https://github.com/imparask/PhishingWebsiteDetectionApp
