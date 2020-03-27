# -*- coding: utf-8 -*-
"""
Created on Sat Mar 21 22:08:32 2020

@author: PARAS
"""
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import FeatureExtraction as fe



splitted_data = pd.read_csv("Data/splitted_data3.csv")

X = splitted_data.iloc[:,0:13].values.astype(int)
y = splitted_data.iloc[:,13].values.astype(int)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=np.random.seed(7))




from keras.models import Sequential
from keras.layers import Dense
from keras.optimizers import *

# Model building using the Sequential API
model = Sequential()

model.add(Dense(40, activation='relu',
          kernel_initializer='uniform',input_dim=X.shape[1]))
model.add(Dense(30, activation='relu',
          kernel_initializer='uniform'))
model.add(Dense(1,  activation='sigmoid', 
          kernel_initializer='uniform'))

model.compile(loss='binary_crossentropy', optimizer=Adam(), metrics=['accuracy'])

model.summary()

history = model.fit(X_train, y_train, batch_size=64, epochs=128, verbose=1)

scores = model.evaluate(X_test, y_test)
print('\nAccuracy score of the Neural Network with basic hyperparameter settings {0:.2f}%'.format(scores[1]*100))


keras_file = "urlKeras.h5"
model.save(keras_file)

url = "http://paypal.gb-ppsweb.com/sd/confirm.php?cmd=process"
data = fe.getAttributes(url)

data.to_csv("Data/data.csv")

print(model.predict([data]))

