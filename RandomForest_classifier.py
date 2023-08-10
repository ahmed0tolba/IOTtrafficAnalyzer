from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score, ConfusionMatrixDisplay
from sklearn import svm, metrics

# Pandas is used for data manipulation
import pandas as pd
# Read in data and display first 5 rows
df = pd.read_csv('uploadedFiles/Joined In depth packet analysis.csv')
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
df= df.loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer"]]
# features= features.drop('blue_fault', axis = 1)


# Saving feature names for later use
feature_list = list(df.columns)
# print(feature_list)
# Convert to numpy array
numpy_array = np.array(df)
# print(numpy_array)

# Using Skicit-learn to split data into training and testing sets
from sklearn.model_selection import train_test_split
# Split the data into training and testing sets
train_features, test_features, train_labels, test_labels = train_test_split(numpy_array, attack_type_labels, test_size = 0.25, stratify = attack_type_labels)
# train_features, test_features, train_labels, test_labels = train_test_split(numpy_array, attack_labels, test_size = 0.25, stratify = attack_labels)

print('Training Features Shape:', train_features.shape)
print('Training Labels Shape:', train_labels.shape)
print('Testing Features Shape:', test_features.shape)
print('Testing Labels Shape:', test_labels.shape)

unique, counts = np.unique(attack_type_labels, return_counts=True)
print(unique)
print(counts)
unique, counts = np.unique(test_labels, return_counts=True)
print(unique)
print(counts)



exit()

print("ANN --- start")
# will not work for MITM and deauth with out oversampling 
import numpy as np
from keras.utils import to_categorical
import matplotlib.pyplot as plt
from imblearn.over_sampling import ADASYN, SMOTE # pip install imbalanced-learn
sm = SMOTE(k_neighbors=2)
X_over, y_over = sm.fit_resample(numpy_array, attack_type_labels)

print('Training data shape : ', X_over.shape, y_over.shape)
print('Testing data shape : ', test_features.shape, test_labels.shape)

classes = np.unique(attack_type_labels)
nClasses = len(classes)
print('Total number of outputs : ', nClasses)
print('Output classes : ', classes)

import tensorflow as tf
from tensorflow.keras import datasets, layers, models
import matplotlib.pyplot as plt

model = tf.keras.models.Sequential()
model.add(tf.keras.layers.Dense(units=100,activation = tf.nn.sigmoid))
model.add(tf.keras.layers.Dense(units=6,activation = tf.nn.sigmoid))

# model.compile(optimizer = tf.keras.optimizers.RMSprop(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy'])  # 0.986
model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 0.987
# model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 0.983  30 epochs , .98 100
# model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 
# model.compile(optimizer = tf.keras.optimizers.Adamax(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # .982
# model.compile(optimizer = tf.keras.optimizers.Adadelta(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # .544
# model.compile(optimizer = tf.keras.optimizers.Adagrad(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # .842
# model.compile(optimizer = tf.keras.optimizers.Adagrad(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # 
print("training ")
model.fit(X_over, y_over, epochs=200,verbose=0) # 200
predictions_array = model.predict(test_features)
predictions = np.argmax(predictions_array, axis=1).astype(int)
print(predictions)
result = confusion_matrix(test_labels, predictions)
print(result)

errors = abs(predictions - test_labels)
# Print out the mean absolute error (mae)
print('ANN Mean Absolute Error:', np.mean(errors), '%.')
print("ANN Accuracy:",metrics.accuracy_score(test_labels, predictions))
print("ANN Precision:",metrics.precision_score(test_labels, predictions,average='micro'))
print("ANN Recall:",metrics.recall_score(test_labels, predictions,average='micro'))

print("ANN ---- end")



print("")
print("")
print("")


print("RF --- start")
# Import the model we are using
from sklearn.ensemble import RandomForestClassifier
# Instantiate model with 1000 decision trees
rf = RandomForestClassifier(n_estimators = 100)
# Train the model on training data
rf.fit(train_features, train_labels)

# Use the forest's predict method on the test data
predictions = rf.predict(test_features).astype(int)
# print(test_features)
# Calculate the absolute errors
errors = abs(predictions - test_labels)
# Print out the mean absolute error (mae)
print('RF Mean Absolute Error:', np.mean(errors), '%.')
print("RF Accuracy:",metrics.accuracy_score(test_labels, predictions))
print("RF Precision:",metrics.precision_score(test_labels, predictions,average='micro'))
print("RF Recall:",metrics.recall_score(test_labels, predictions,average='micro'))
# import pickle
# pickle.dump(rf, open("RandomForestModel.sav", 'wb'))
# loaded_model = pickle.load(open("RandomForestModel.sav", 'rb'))

conf_mat = confusion_matrix(test_labels, predictions)
print(conf_mat)

print(le_attack_type.classes_)

print("RF --- end")


print("")
print("")
print("")



print("KNN --- start")
from sklearn.neighbors import KNeighborsClassifier
number_classes = len(le_attack_type.classes_)
knn = KNeighborsClassifier(n_neighbors=number_classes,weights="distance",leaf_size=100) # weights="distance" very importanct as data is impalanced
knn.fit(numpy_array, attack_type_labels)
predictions = knn.predict(test_features)
errors = abs(predictions - test_labels)
conf_mat = confusion_matrix(test_labels, predictions)
print(conf_mat)
print('KNN Mean Absolute Error:', np.mean(errors), '%.')
print("KNN Accuracy:",metrics.accuracy_score(test_labels, predictions))
print("KNN Precision:",metrics.precision_score(test_labels, predictions,average='micro'))
print("KNN Recall:",metrics.recall_score(test_labels, predictions,average='micro'))

print("KNN --- end")

# exit()

print("")
print("")
print("")


print("SVM --- start")

#Import svm model

#Create a svm Classifier
# clf = svm.LinearSVC(penalty="l1",loss="squared_hinge",dual=False,multi_class="crammer_singer", max_iter=10000) # Linear Kernel  .2844
# clf = svm.LinearSVC(max_iter=1000) # Linear Kernel  # .892
# clf = svm.LinearSVC(penalty="l1",dual=False,max_iter=1000) # Linear Kernel  # .87
# clf = svm.LinearSVC(fit_intercept=True, penalty="l2",loss="squared_hinge",class_weight="balanced", max_iter=10000) # Linear Kernel  # .87
# clf = svm.SVC() # .52
# clf = svm.SVC(C=100) # .7
# clf = svm.SVC(C=100,gamma="auto") # .993
# clf = svm.SVC(C=100,gamma="auto") # .993
clf = svm.SVC(C=100,gamma=10) # .999
# clf = svm.LinearSVC(penalty="l1",loss="squared_hinge",dual=False,max_iter=1000) # Linear Kernel  # .87
# clf = svm.LinearSVC(penalty="l1",loss="squared_hinge",multi_class="crammer_singer",dual=False,max_iter=1000) # Linear Kernel  # .3
# clf = svm.LinearSVC(penalty="l1",loss="squared_hinge",multi_class="ovr",dual=False,max_iter=1000) # Linear Kernel  # .86
# clf = svm.LinearSVC(multi_class="ovr",max_iter=1000) # Linear Kernel  # .86
# clf = svm.LinearSVC(max_iter=10000) # Linear Kernel  # .879
# clf = svm.SVC(kernel='rbf') # Linear Kernel  # kernel='rbf' # kernel='linear' # .528
# clf = svm.SVC(decision_function_shape='ovo') # Linear Kernel  # .5333
# clf = svm.SVR() # Linear Kernel  # .352
# clf = svm.SVC(kernel='poly') # Linear Kernel  # .444
#Train the model using the training sets
clf.fit(numpy_array, attack_type_labels)
#Predict the response for test dataset
y_pred = clf.predict(test_features).astype(int)
conf_mat = confusion_matrix(test_labels, y_pred)
print(conf_mat)
print("SVM Accuracy:",metrics.accuracy_score(test_labels, y_pred))
print("SVM Precision:",metrics.precision_score(test_labels, y_pred,average='micro'))
print("SVM Recall:",metrics.recall_score(test_labels, y_pred,average='micro'))

print("RF --- end")

print("")
print("")
print("")


