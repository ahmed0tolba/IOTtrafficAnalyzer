from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, ConfusionMatrixDisplay
from sklearn import svm, metrics
from sklearn.model_selection import train_test_split
import xgboost as xgb # pip install xgboost
from xgboost import XGBClassifier

# Pandas is used for data manipulation
import pandas as pd

from keras.layers import Dense,Conv2D,MaxPooling2D,UpSampling2D
from keras import Input, Model
from keras.datasets import mnist
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import VotingClassifier

import numpy as np
from keras.utils import to_categorical
import matplotlib.pyplot as plt
from imblearn.over_sampling import ADASYN, SMOTE # pip install imbalanced-learn
import seaborn as sn
import matplotlib

# Read in data and display first 5 rows
df = pd.read_csv('multi/_Joined In depth packet analysis.csv')
df.fillna(0, inplace=True)
print(type(df))
print(df.head(5))

print('The shape of our features is:', df.shape)

# Descriptive statistics for each column
print(df.describe())

le_Protocol = LabelEncoder()
label_Protocol = le_Protocol.fit_transform(df['Protocol'])
df.drop("Protocol", axis=1, inplace=True)
df["Protocol"] = label_Protocol

le_attack_type = LabelEncoder()
label_attack_type = le_attack_type.fit_transform(df['attack type'])
df.drop("attack type", axis=1, inplace=True)
df["attack type"] = label_attack_type

le_isserver = LabelEncoder()
label_isserver = le_isserver.fit_transform(df['IsServer'])
df.drop("IsServer", axis=1, inplace=True)
df["IsServer"] = label_isserver

# Use numpy to convert to arrays
import numpy as np
# Labels are the values we want to predict
attack_labels = np.array(df.loc[: , "attack"])
attack_type_labels = np.array(df.loc[: , "attack type"])
# print("attack_labels", attack_labels)
# print("attack_type_labels", attack_type_labels)
# Remove the labels from the features
# axis 1 refers to the columns
df= df.loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","IOT_Respond_401"]]
# features= features.drop('blue_fault', axis = 1)

# Saving feature names for later use
feature_list = list(df.columns)
# print(feature_list)
# Convert to numpy array
numpy_array = np.array(df)
# print(numpy_array)


sm = SMOTE(k_neighbors=2)
numpy_array_over, attack_type_labels_over = sm.fit_resample(numpy_array, attack_type_labels)

# Split the data into training and testing sets
train_features, test_features, train_labels, test_labels = train_test_split(numpy_array, attack_type_labels, test_size = 0.25, stratify = attack_type_labels)
train_features_over, test_features_over, train_labels_over, test_labels_over = train_test_split(numpy_array_over, attack_type_labels_over, test_size = 0.25, stratify = attack_type_labels_over)
# train_features, test_features, train_labels, test_labels = train_test_split(numpy_array, attack_labels, test_size = 0.25, stratify = attack_labels)


print('Training Features Shape:', train_features_over.shape)
print('Training Labels Shape:', train_labels_over.shape)
print('Testing Features Shape:', test_features.shape)
print('Testing Labels Shape:', test_labels.shape)

unique, counts = np.unique(attack_type_labels, return_counts=True)
print(unique)
print(counts)
unique, counts = np.unique(train_labels_over, return_counts=True)
print(unique)
print(counts)
unique, counts = np.unique(test_labels, return_counts=True)
print(unique)
print(counts)

classes = np.unique(attack_type_labels)
nClasses = len(classes)
print('Total number of outputs : ', nClasses)
print('Output classes : ', classes)
print('Output classes : ',le_attack_type.classes_)

confussion_matrix_labels = ['Normal','MITM','UDP','Password','Deauth','DOS','Scan']

colors = ["#90AFC5", "#90AFC5"]
cmap = matplotlib.colors.LinearSegmentedColormap.from_list("", colors)

print("SVM --- start")

#Import svm model

#Create a svm Classifier
# over
# poly .293
# rbf .37
# 1 1 0.001 rbf .965
# 2 1 0.001 rbf .967
# 5 1 0.001 rbf .969
# 10 1 0.001 rbf .966
# 100 1 0.001 rbf .966
# 1 1 0.001 poly 
# raw
# 100 100 0.001 rbf .9948
# 10 200 0.001 rbf .991   best
# 1 1 0.001 rbf .991
# 100 10 0.001 rbf ovo .991
# 1 100 0.001 rbf ovo .990
# 10 100 0.001 rbf ovo .991
# 20 100 0.001 rbf ovo .99
# 50 100 0.001 rbf ovo .99+
# 100 1 1e-06 rbf ovo best 80 20 .96
# 1 1 1e-06 rbf ovo best 81 18 .97
# 1 100 1e-06 rbf ovo best 81 18 .97
kernel='rbf'
C = 1
gamma = 1
tol = .000001
decision_function_shape="ovo"
print(C , gamma , tol , kernel,decision_function_shape)
svm_model = svm.SVC(C=C ,gamma=gamma,tol=tol, kernel=kernel,decision_function_shape="ovo") # .97   C=1,gamma=1,tol=.1,
#Train the model using the training sets
svm_model.fit(train_features_over, train_labels_over)
#Predict the response for test dataset
y_pred = svm_model.predict(test_features_over)

print("SVM Accuracy:",metrics.accuracy_score(test_labels_over, y_pred))
print("SVM Precision:",metrics.precision_score(test_labels_over, y_pred,average='micro'))
print("SVM Recall:",metrics.recall_score(test_labels_over, y_pred,average='micro'))

conf_mat = confusion_matrix(test_labels_over, y_pred)
conf_mat_norm = np.round(conf_mat.astype('float') / conf_mat.sum(axis=1)[:, np.newaxis] *100,2)
print(conf_mat_norm.astype(int))
result = pd.DataFrame(conf_mat_norm,confussion_matrix_labels,confussion_matrix_labels)
ax = sn.heatmap(result, annot=True, annot_kws={"size": 9},xticklabels = True,cbar=False,square=True,cmap=cmap) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("SVM Confusion Matrix")
plt.show()

print("SVM --- end \n\n\n")

# exit()

print("KNN --- start")
from sklearn.neighbors import KNeighborsClassifier
number_classes = len(le_attack_type.classes_)
knn = KNeighborsClassifier(n_neighbors=1,weights="distance",leaf_size=1) # weights="distance" very importanct as data is impalanced 
knn.fit(train_features_over, train_labels_over)
predictions = knn.predict(test_features_over)
print("KNN Precision:",metrics.precision_score(test_labels_over, predictions,average='micro')) # 0.9956
print("KNN Recall:",metrics.recall_score(test_labels_over, predictions,average='micro'))

# print("KNN Accuracy:",metrics.accuracy_score)

errors = abs(predictions - test_labels_over)
conf_mat = confusion_matrix(test_labels_over, predictions)
conf_mat_norm = np.round(conf_mat.astype('float') / conf_mat.sum(axis=1)[:, np.newaxis] *100,2)
print(conf_mat_norm.astype(int))
result = pd.DataFrame(conf_mat_norm,confussion_matrix_labels,confussion_matrix_labels)
ax = sn.heatmap(result, annot=True, annot_kws={"size": 9},xticklabels = True,cbar=False,square=True,cmap=cmap) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("KNN Confusion Matrix")
plt.show()




print("KNN --- end \n\n\n")

# exit()

print("RF --- start")
# Import the model we are using
from sklearn.ensemble import RandomForestClassifier
# Instantiate model with 1000 decision trees
rf = RandomForestClassifier(n_estimators = 30)
# Train the model on training data
rf.fit(train_features_over, train_labels_over)

# Use the forest's predict method on the test data
predictions = rf.predict(test_features_over)
# print(test_features)
# Calculate the absolute errors
errors = abs(predictions - test_labels_over)
# Print out the mean absolute error (mae)
print('RF Mean Absolute Error:', np.mean(errors), '%.')
print("RF Accuracy:",metrics.accuracy_score(test_labels_over, predictions))  # .99937
print("RF Precision:",metrics.precision_score(test_labels_over, predictions,average='micro'))
print("RF Recall:",metrics.recall_score(test_labels_over, predictions,average='micro'))
# import pickle
# pickle.dump(rf, open("RandomForestModel.sav", 'wb'))
# loaded_model = pickle.load(open("RandomForestModel.sav", 'rb'))

conf_mat = confusion_matrix(test_labels_over, predictions)
conf_mat_norm = np.round(conf_mat.astype('float') / conf_mat.sum(axis=1)[:, np.newaxis] *100,2)
print("confusion_matrix \n", conf_mat_norm)
result = pd.DataFrame(conf_mat_norm,confussion_matrix_labels,confussion_matrix_labels)
ax = sn.heatmap(result, annot=True, annot_kws={"size": 9},xticklabels = True,cbar=False,square=True,cmap=cmap) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("RF Confusion Matrix")
plt.show()

# print(le_attack_type.classes_)

print("RF --- end \n\n\n")

# exit()

print("XGB skilearn ---- start")

XGBskilearnmodel = GradientBoostingClassifier(n_estimators=100, learning_rate=.70,max_depth=7, random_state=0).fit(train_features_over, train_labels_over) # 0.999
score = XGBskilearnmodel.score(test_features_over, test_labels_over)
predictions = XGBskilearnmodel.predict(test_features_over)
conf_mat = confusion_matrix(test_labels_over, predictions)
conf_mat_norm = conf_mat.astype('float') / conf_mat.sum(axis=1)[:, np.newaxis] *100

print(score)
print("confusion_matrix \n", conf_mat_norm.astype(int))

df_confusion_matrix_XGB_skilearn = pd.DataFrame(conf_mat_norm,confussion_matrix_labels,confussion_matrix_labels)
ax = sn.heatmap(df_confusion_matrix_XGB_skilearn, annot=True, annot_kws={"size": 9},xticklabels = True,cbar=False,square=True,cmap=cmap) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("XGB skilearn Confusion Matrix")
plt.show()

print("XGB skilearn ---- end \n\n\n")


# exit()
print("XGB boost ---- start")

XGBmodel = XGBClassifier()
XGBmodel.fit(train_features_over, train_labels_over)
predictions = XGBmodel.predict(test_features_over)

confmat = confusion_matrix(test_labels_over, predictions)
conf_mat_norm = conf_mat.astype('float') / conf_mat.sum(axis=1)[:, np.newaxis] *100

print("confusion_matrix \n", conf_mat_norm.astype('int'))

errors = abs(predictions - test_labels_over)
# Print out the mean absolute error (mae)
print('XGB boost Mean Absolute Error:', np.mean(errors), '%.')
print("XGB boost Accuracy:",metrics.accuracy_score(test_labels_over, predictions))
print("XGB boost Precision:",metrics.precision_score(test_labels_over, predictions,average='micro'))
print("XGB boost Recall:",metrics.recall_score(test_labels_over, predictions,average='micro'))
print("XGB boost ---- end \n\n\n")

df_confusion_matrix_XGB = pd.DataFrame(conf_mat_norm,confussion_matrix_labels,confussion_matrix_labels)
ax = sn.heatmap(df_confusion_matrix_XGB, annot=True, annot_kws={"size": 9},xticklabels = True,cbar=False,square=True,cmap=cmap) # font size
ax.set(xlabel="Actual Values", ylabel="Predicted Values")
ax.xaxis.tick_top()
ax.set_title("XGB boost Confusion Matrix")
plt.show()

# exit()

print("autoencoder ---- start")


import tensorflow as tf
from keras import datasets, layers, models
import matplotlib.pyplot as plt

autoencoder_model = tf.keras.models.Sequential()  # 84 normal TP
autoencoder_model.add(tf.keras.layers.Dense(units=80,activation = tf.nn.sigmoid))
autoencoder_model.add(tf.keras.layers.Dense(units=24,activation = tf.nn.sigmoid))
autoencoder_model.add(tf.keras.layers.Dense(units=6,activation = tf.nn.leaky_relu))
autoencoder_model.add(tf.keras.layers.Dense(units=7,activation = tf.nn.sigmoid))

autoencoder_model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 0.987
print("training ")
autoencoder_model.fit(train_features_over, train_labels_over, epochs=100,verbose=2) # 200
predictions_array = autoencoder_model.predict(test_features_over)
predictions = np.argmax(predictions_array, axis=1).astype(int)
print("predictions", predictions)
conf_mat = confusion_matrix(test_labels_over, predictions)
conf_mat_norm = conf_mat.astype('float') / conf_mat.sum(axis=1)[:, np.newaxis] *100

print("confusion_matrix \n", conf_mat_norm.astype('int'))
result = pd.DataFrame(conf_mat_norm,confussion_matrix_labels,confussion_matrix_labels)
ax = sn.heatmap(result, annot=True, annot_kws={"size": 9},xticklabels = True,cbar=False,square=True,cmap=cmap) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("autoencoder Confusion Matrix")
plt.show()

errors = abs(predictions - test_labels_over)
# Print out the mean absolute error (mae)
print('autoencoder Mean Absolute Error:', np.mean(errors), '%.')
print("autoencoder Accuracy:",metrics.accuracy_score(test_labels_over, predictions))
print("autoencoder Precision:",metrics.precision_score(test_labels_over, predictions,average='micro'))
print("autoencoder Recall:",metrics.recall_score(test_labels_over, predictions,average='micro'))

print("autoencoder ---- end \n\n\n")


# exit()


print("ANN --- start")
# will not work for MITM and deauth without oversampling 
import numpy as np
from keras.utils import to_categorical
import matplotlib.pyplot as plt
from imblearn.over_sampling import ADASYN, SMOTE # pip install imbalanced-learn


import tensorflow as tf
from keras import datasets, layers, models
import matplotlib.pyplot as plt

ANN_model = tf.keras.models.Sequential()
ANN_model.add(tf.keras.layers.Dense(units=100,activation = tf.nn.sigmoid))
ANN_model.add(tf.keras.layers.Dense(units=7,activation = tf.nn.sigmoid))

ANN_model.compile(optimizer = tf.keras.optimizers.RMSprop(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy'])  # 0.986 95 normal TP
# ANN_model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 0.987
# ANN_model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 0.983  30 epochs , .98 100
# ANN_model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 
# ANN_model.compile(optimizer = tf.keras.optimizers.Adamax(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # .982 96 normal TP
# ANN_model.compile(optimizer = tf.keras.optimizers.Adadelta(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # .544
# ANN_model.compile(optimizer = tf.keras.optimizers.Adagrad(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # .842
# ANN_model.compile(optimizer = tf.keras.optimizers.Adagrad(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # 
print("training ")
ANN_model.fit(train_features_over, train_labels_over, epochs=100,verbose=1) # 200
predictions_array = ANN_model.predict(test_features_over)
predictions = np.argmax(predictions_array, axis=1).astype(int)
print(predictions)

errors = abs(predictions - test_labels_over)
# Print out the mean absolute error (mae)
print('ANN Mean Absolute Error:', np.mean(errors), '%.') # 0.03600500939261114 %.
print("ANN Accuracy:",metrics.accuracy_score(test_labels_over, predictions))
print("ANN Precision:",metrics.precision_score(test_labels_over, predictions,average='micro'))
print("ANN Recall:",metrics.recall_score(test_labels_over, predictions,average='micro'))

conf_mat = confusion_matrix(test_labels_over, predictions)
conf_mat_norm = conf_mat.astype('float') / conf_mat.sum(axis=1)[:, np.newaxis] *100

print(conf_mat_norm.astype('int'))
result = pd.DataFrame(conf_mat_norm,confussion_matrix_labels,confussion_matrix_labels)
ax = sn.heatmap(result, annot=True, annot_kws={"size": 9},xticklabels = True,cbar=False,square=True,cmap=cmap) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("ANN Confusion Matrix")
plt.show()


print("ANN ---- end \n\n\n")

# exit()

print("CNN ---- start")

import numpy as np
from keras.utils import to_categorical
import matplotlib.pyplot as plt
from imblearn.over_sampling import ADASYN, SMOTE # pip install imbalanced-learn

classes = np.unique(attack_type_labels)
nClasses = len(classes)
print('Total number of outputs : ', nClasses)
print('Output classes : ', classes)
print('Output classes : ',le_attack_type.classes_)
import tensorflow as tf
from keras import datasets, layers, models
import matplotlib.pyplot as plt

cnn_model = tf.keras.models.Sequential()
cnn_model.add(tf.keras.layers.Dense(units=70,activation = tf.nn.sigmoid))
cnn_model.add(tf.keras.layers.Dense(units=25,activation = tf.nn.sigmoid))
cnn_model.add(tf.keras.layers.Dense(units=7,activation = tf.nn.sigmoid))

cnn_model.compile(optimizer = tf.keras.optimizers.RMSprop(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy'])  # 0.986 95 normal TP
# cnn_model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 0.987
print("training ")
cnn_model.fit(train_features_over, train_labels_over, epochs=200,verbose=1) # 200
predictions_array = cnn_model.predict(test_features_over)
predictions = np.argmax(predictions_array, axis=1).astype(int)
print("predictions", predictions)
conf_mat = confusion_matrix(test_labels_over, predictions)
conf_mat_norm = conf_mat.astype('float') / conf_mat.sum(axis=1)[:, np.newaxis] *100

print("confusion_matrix \n", conf_mat_norm.astype('int'))
result = pd.DataFrame(conf_mat_norm,confussion_matrix_labels,confussion_matrix_labels)
ax = sn.heatmap(result, annot=True, annot_kws={"size": 9},xticklabels = True,cbar=False,square=True,cmap=cmap) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("CNN Confusion Matrix")
plt.show()

errors = abs(predictions - test_labels_over)
# Print out the mean absolute error (mae)
print('CNN Mean Absolute Error:', np.mean(errors), '%.')
print("CNN Accuracy:",metrics.accuracy_score(test_labels_over, predictions))
print("CNN Precision:",metrics.precision_score(test_labels_over, predictions,average='micro'))
print("CNN Recall:",metrics.recall_score(test_labels_over, predictions,average='micro'))

print("CNN ---- end \n\n\n")


print("Ensemble ---- start")

ensemble_model = VotingClassifier(estimators=[('svc', svm_model),('knn', knn), ('rf', rf),('XGBboost', XGBmodel),('XGBskilearnmodel',XGBskilearnmodel)], voting ='hard',weights=[1,1,1,1,1]) # ('svc', svm_model), ,
ensemble_model.fit(train_features_over, train_labels_over)
predictions = ensemble_model.predict(test_features)
print("predictions", predictions)
conf_mat = confusion_matrix(test_labels, predictions)
conf_mat_norm = conf_mat.astype('float') / conf_mat.sum(axis=1)[:, np.newaxis] *100

print("confusion_matrix \n", conf_mat_norm.astype('int'))
result1 = pd.DataFrame(conf_mat_norm,confussion_matrix_labels,confussion_matrix_labels)
ax = sn.heatmap(result1, annot=True, annot_kws={"size": 9},xticklabels = True,cbar=False,square=True,cmap=cmap) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
ax.set_title("ensemble Confusion Matrix")
plt.show()

errors = abs(predictions - test_labels)
# Print out the mean absolute error (mae)
print('ensemble Mean Absolute Error:', np.mean(errors), '%.')
print("ensemble Accuracy:",metrics.accuracy_score(test_labels, predictions))
print("ensemble Precision:",metrics.precision_score(test_labels, predictions,average='micro'))
print("ensemble Recall:",metrics.recall_score(test_labels, predictions,average='micro'))

print("Ensemble ---- end \n\n\n")

# print("encoder decoder Cancelled ---- end")
# encoding_dim = 4 
# input_row = Input(shape=(len(feature_list),))
# # encoded representation of input
# encoded = Dense(encoding_dim, activation='sigmoid')(input_row)
# # decoded representation of code 
# decoded = Dense(1, activation='sigmoid')(encoded)
# # Model which take input image and shows decoded images
# autoencoder = Model(input_row, decoded)

# # This model shows encoded images
# encoder = Model(input_row, encoded)
# # Creating a decoder model
# encoded_input = Input(shape=(encoding_dim,))
# # last layer of the autoencoder model
# decoder_layer = autoencoder.layers[-1]
# # decoder model
# decoder = Model(encoded_input, decoder_layer(encoded_input))

# autoencoder.compile(optimizer='adam', loss='binary_crossentropy')

# autoencoder.fit(train_features, train_labels,epochs=15,batch_size=256,validation_data=(test_features, test_labels))

# encoded_row = encoder.predict(test_features)
# decoded_row = (decoder.predict(encoded_row) * 6).astype(int)

# decoded_row_ar = np.array([ar[0] for ar in decoded_row])
# test_labels_ar = np.array([float(ar) for ar in test_labels])

# print(test_labels_ar)
# print(decoded_row_ar)
# print(type(decoded_row_ar))


# errors = abs(test_labels_ar - decoded_row_ar)
# # Print out the mean absolute error (mae)
# print('autoencoder Mean Absolute Error:', np.mean(errors), '%.')

# result = confusion_matrix(test_labels_ar, decoded_row_ar)
# print("autoencoder confusion_matrix " ,result)

# print("autoencoder ---- end \n\n\n")




