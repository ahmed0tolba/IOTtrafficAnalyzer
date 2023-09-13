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
unique, counts = np.unique(train_labels, return_counts=True)
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

confussion_matrix_labels = ['Normal','MITM','UDP','password','deauth','dos','scan']

print("XGB boost ---- start")

model = XGBClassifier()
model.fit(train_features, train_labels)
predictions = model.predict(test_features)

result = confusion_matrix(test_labels, predictions)
print("confusion_matrix \n", result)

errors = abs(predictions - test_labels)
# Print out the mean absolute error (mae)
print('XGB boost Mean Absolute Error:', np.mean(errors), '%.')
print("XGB boost Accuracy:",metrics.accuracy_score(test_labels, predictions))
print("XGB boost Precision:",metrics.precision_score(test_labels, predictions,average='micro'))
print("XGB boost Recall:",metrics.recall_score(test_labels, predictions,average='micro'))
print("XGB boost ---- end \n\n\n")

# 'Accent', 'Accent_r', 'Blues', 'Blues_r', 'BrBG', 'BrBG_r', 'BuGn', 'BuGn_r', 'BuPu', 'BuPu_r', 'CMRmap', 'CMRmap_r', 'Dark2', 'Dark2
# _r', 'GnBu', 'GnBu_r', 'Greens', 'Greens_r', 'Greys', 'Greys_r', 'OrRd', 'OrRd_r', 'Oranges', 'Oranges_r', 'PRGn', 'PRGn_r', 'Paired', 'Paired_r', 'Pastel1', 'Pastel1_r', 'Pastel2', 'Pastel2_r', 'PiYG', 'PiYG
# _r', 'PuBu', 'PuBuGn', 'PuBuGn_r', 'PuBu_r', 'PuOr', 'PuOr_r', 'PuRd', 'PuRd_r', 'Purples', 'Purples_r', 'RdBu', 'RdBu_r', 'RdGy', 'RdGy_r', 'RdPu', 'RdPu_r', 'RdYlBu', 'RdYlBu_r', 'RdYlGn', 'RdYlGn_r', 'Reds
# ', 'Reds_r', 'Set1', 'Set1_r', 'Set2', 'Set2_r', 'Set3', 'Set3_r', 'Spectral', 'Spectral_r', 'Wistia', 'Wistia_r', 'YlGn', 'YlGnBu', 'YlGnBu_r', 'YlGn_r', 'YlOrBr', 'YlOrBr_r', 'YlOrRd', 'YlOrRd_r', 'afmhot',
#  'afmhot_r', 'autumn', 'autumn_r', 'binary', 'binary_r', 'bone', 'bone_r', 'brg', 'brg_r', 'bwr', 'bwr_r', 'cividis', 'cividis_r', 'cool', 'cool_r', 'coolwarm', 'coolwarm_r', 'copper', 'copper_r', 'crest', 'c
# rest_r', 'cubehelix', 'cubehelix_r', 'flag', 'flag_r', 'flare', 'flare_r', 'gist_earth', 'gist_earth_r', 'gist_gray', 'gist_gray_r', 'gist_heat', 'gist_heat_r', 'gist_ncar', 'gist_ncar_r', 'gist_rainbow', 'gi
# st_rainbow_r', 'gist_stern', 'gist_stern_r', 'gist_yarg', 'gist_yarg_r', 'gnuplot', 'gnuplot2', 'gnuplot2_r', 'gnuplot_r', 'gray', 'gray_r', 'hot', 'hot_r', 'hsv', 'hsv_r', 'icefire', 'icefire_r', 'inferno',
# 'inferno_r', 'jet', 'jet_r', 'magma', 'magma_r', 'mako', 'mako_r', 'nipy_spectral', 'nipy_spectral_r', 'ocean', 'ocean_r', 'pink', 'pink_r', 'plasma', 'plasma_r', 'prism', 'prism_r', 'rainbow', 'rainbow_r', '
# rocket', 'rocket_r', 'seismic', 'seismic_r', 'spring', 'spring_r', 'summer', 'summer_r', 'tab10', 'tab10_r', 'tab20', 'tab20_r', 'tab20b', 'tab20b_r', 'tab20c', 'tab20c_r', 'terrain', 'terrain_r', 'turbo', 't
# urbo_r', 'twilight', 'twilight_r', 'twilight_shifted', 'twilight_shifted_r', 'viridis', 'viridis_r', 'vlag', 'vlag_r', 'winter', 'winter_r'
colors = ["#90AFC5", "#90AFC5"]
cmap = matplotlib.colors.LinearSegmentedColormap.from_list("", colors)

df_cm = pd.DataFrame(result,confussion_matrix_labels,confussion_matrix_labels)
# plt.figure(figsize=(10,7))
# for label size
ax = sn.heatmap(df_cm, annot=True, annot_kws={"size": 9},xticklabels = True,cbar=False,square=True,cmap=cmap) # font size
ax.set(xlabel="", ylabel="")
ax.xaxis.tick_top()
plt.show()

exit()


print("XGB skilearn ---- start")

clf = GradientBoostingClassifier(n_estimators=1000, learning_rate=.70,max_depth=7, random_state=0).fit(train_features, train_labels) # 0.999
score = clf.score(test_features, test_labels)
predictions = clf.predict(test_features)
result = confusion_matrix(test_labels, predictions)

print(score)
print("confusion_matrix \n", result)

print("XGB skilearn ---- end \n\n\n")


exit()


print("Ensemble ---- start")



print("Ensemble ---- end \n\n\n")


exit()



print("autoencoder ---- start")
sm = SMOTE(k_neighbors=2)
X_over, y_over = sm.fit_resample(numpy_array, attack_type_labels)

print('Training data shape : ', X_over.shape, y_over.shape)
print('Testing data shape : ', test_features.shape, test_labels.shape)


import tensorflow as tf
from keras import datasets, layers, models
import matplotlib.pyplot as plt

model = tf.keras.models.Sequential()
model.add(tf.keras.layers.Dense(units=100,activation = tf.nn.sigmoid))
model.add(tf.keras.layers.Dense(units=50,activation = tf.nn.sigmoid))
model.add(tf.keras.layers.Dense(units=6,activation = tf.nn.leaky_relu))
model.add(tf.keras.layers.Dense(units=7,activation = tf.nn.sigmoid))

model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 0.987
print("training ")
model.fit(X_over, y_over, epochs=10,verbose=1) # 200
predictions_array = model.predict(test_features)
predictions = np.argmax(predictions_array, axis=1).astype(int)
print("predictions", predictions)
result = confusion_matrix(test_labels, predictions)
print("confusion_matrix \n", result)

errors = abs(predictions - test_labels)
# Print out the mean absolute error (mae)
print('autoencoder Mean Absolute Error:', np.mean(errors), '%.')
print("autoencoder Accuracy:",metrics.accuracy_score(test_labels, predictions))
print("autoencoder Precision:",metrics.precision_score(test_labels, predictions,average='micro'))
print("autoencoder Recall:",metrics.recall_score(test_labels, predictions,average='micro'))

print("autoencoder ---- end \n\n\n")


exit()



print("ANN --- start")
# will not work for MITM and deauth without oversampling 
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
print('Output classes : ', le_attack_type.classes_)

import tensorflow as tf
from keras import datasets, layers, models
import matplotlib.pyplot as plt

model = tf.keras.models.Sequential()
model.add(tf.keras.layers.Dense(units=100,activation = tf.nn.sigmoid))
model.add(tf.keras.layers.Dense(units=7,activation = tf.nn.sigmoid))

# model.compile(optimizer = tf.keras.optimizers.RMSprop(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy'])  # 0.986
model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 0.987
# model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 0.983  30 epochs , .98 100
# model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 
# model.compile(optimizer = tf.keras.optimizers.Adamax(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # .982
# model.compile(optimizer = tf.keras.optimizers.Adadelta(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # .544
# model.compile(optimizer = tf.keras.optimizers.Adagrad(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # .842
# model.compile(optimizer = tf.keras.optimizers.Adagrad(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=['accuracy']) # 
print("training ")
model.fit(X_over, y_over, epochs=200,verbose=1) # 200
predictions_array = model.predict(test_features)
predictions = np.argmax(predictions_array, axis=1).astype(int)
print(predictions)
result = confusion_matrix(test_labels, predictions)
print(result)

errors = abs(predictions - test_labels)
# Print out the mean absolute error (mae)
print('ANN Mean Absolute Error:', np.mean(errors), '%.') # 0.03600500939261114 %.
print("ANN Accuracy:",metrics.accuracy_score(test_labels, predictions))
print("ANN Precision:",metrics.precision_score(test_labels, predictions,average='micro'))
print("ANN Recall:",metrics.recall_score(test_labels, predictions,average='micro'))

print("ANN ---- end \n\n\n")



exit()

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
print("confusion_matrix \n", conf_mat)

print(le_attack_type.classes_)

print("RF --- end \n\n\n")

exit()





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

print("KNN --- end \n\n\n")

exit()


print("SVM --- start")

#Import svm model

#Create a svm Classifier
clf = svm.SVC(C=100,gamma=10) # .999
#Train the model using the training sets
clf.fit(numpy_array, attack_type_labels)
#Predict the response for test dataset
y_pred = clf.predict(test_features).astype(int)
conf_mat = confusion_matrix(test_labels, y_pred)
print(conf_mat)
print("SVM Accuracy:",metrics.accuracy_score(test_labels, y_pred))
print("SVM Precision:",metrics.precision_score(test_labels, y_pred,average='micro'))
print("SVM Recall:",metrics.recall_score(test_labels, y_pred,average='micro'))

print("RF --- end \n\n\n")


exit()

print("CNN ---- start")

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
print('Output classes : ',le_attack_type.classes_)
import tensorflow as tf
from keras import datasets, layers, models
import matplotlib.pyplot as plt

model = tf.keras.models.Sequential()
model.add(tf.keras.layers.Dense(units=100,activation = tf.nn.sigmoid))
model.add(tf.keras.layers.Dense(units=7,activation = tf.nn.sigmoid))

model.compile(optimizer = tf.keras.optimizers.Adam(), loss =tf.keras.losses.SparseCategoricalCrossentropy(), metrics=tf.keras.metrics.BinaryAccuracy()) # 0.987
print("training ")
model.fit(X_over, y_over, epochs=10,verbose=1) # 200
predictions_array = model.predict(test_features)
predictions = np.argmax(predictions_array, axis=1).astype(int)
print("predictions", predictions)
result = confusion_matrix(test_labels, predictions)
print("confusion_matrix \n", result)

errors = abs(predictions - test_labels)
# Print out the mean absolute error (mae)
print('CNN Mean Absolute Error:', np.mean(errors), '%.')
print("CNN Accuracy:",metrics.accuracy_score(test_labels, predictions))
print("CNN Precision:",metrics.precision_score(test_labels, predictions,average='micro'))
print("CNN Recall:",metrics.recall_score(test_labels, predictions,average='micro'))

print("CNN ---- end \n\n\n")



print("encoder decoder Cancelled ---- end")
encoding_dim = 4 
input_row = Input(shape=(len(feature_list),))
# encoded representation of input
encoded = Dense(encoding_dim, activation='sigmoid')(input_row)
# decoded representation of code 
decoded = Dense(1, activation='sigmoid')(encoded)
# Model which take input image and shows decoded images
autoencoder = Model(input_row, decoded)

# This model shows encoded images
encoder = Model(input_row, encoded)
# Creating a decoder model
encoded_input = Input(shape=(encoding_dim,))
# last layer of the autoencoder model
decoder_layer = autoencoder.layers[-1]
# decoder model
decoder = Model(encoded_input, decoder_layer(encoded_input))

autoencoder.compile(optimizer='adam', loss='binary_crossentropy')

autoencoder.fit(train_features, train_labels,epochs=15,batch_size=256,validation_data=(test_features, test_labels))

encoded_row = encoder.predict(test_features)
decoded_row = (decoder.predict(encoded_row) * 6).astype(int)

decoded_row_ar = np.array([ar[0] for ar in decoded_row])
test_labels_ar = np.array([float(ar) for ar in test_labels])

print(test_labels_ar)
print(decoded_row_ar)
print(type(decoded_row_ar))


errors = abs(test_labels_ar - decoded_row_ar)
# Print out the mean absolute error (mae)
print('autoencoder Mean Absolute Error:', np.mean(errors), '%.')

result = confusion_matrix(test_labels_ar, decoded_row_ar)
print("autoencoder confusion_matrix " ,result)

print("autoencoder ---- end \n\n\n")




