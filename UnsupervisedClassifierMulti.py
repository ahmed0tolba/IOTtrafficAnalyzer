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

from keras.utils import to_categorical
import matplotlib.pyplot as plt
from imblearn.over_sampling import ADASYN, SMOTE # pip install imbalanced-learn
import seaborn as sn
import matplotlib
from sklearn.cluster import KMeans , AffinityPropagation , MiniBatchKMeans , SpectralClustering , AgglomerativeClustering, Birch
from sklearn import mixture

# Read in data and display first 5 rows
df = pd.read_csv('multi/_Joined In depth packet analysis.csv')
df.fillna(0, inplace=True)
# print(type(df))
# print(df.head(5))


# Descriptive statistics for each column
# print(df.describe())

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

# Labels are the values we want to predict
attack_labels = np.array(df.loc[: , "attack"])
attack_type_labels = np.array(df.loc[: , "attack type"])
# print("attack_labels", attack_labels)
# print("attack_type_labels", attack_type_labels)
# Remove the labels from the features
# axis 1 refers to the columns
df_important= df.loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","IOT_Respond_401"]]
df['attack'].replace(0, 'Benign',inplace=True)
df['attack'].replace(1, 'Malignant',inplace=True)

# df_important= df.loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","attack"]]
df_Benign_important = df.loc[df['attack'] == 'Benign'].loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","IOT_Respond_401"]]
df_Malignant_important = df.loc[df['attack'] == 'Malignant'].loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","IOT_Respond_401"]]
X = np.array(df_important)

print('The shape of our features is:', df_important.shape)
classes = np.unique(attack_type_labels)
nClasses = len(classes)
print('Total number of outputs : ', nClasses)
print('Output classes : ', classes)
print('Output classes : ',le_attack_type.classes_)
unique, counts = np.unique(attack_type_labels, return_counts=True)
print(counts)
# Descriptive statistics for each column
# print(df_important.describe())


# print(X)

def get_indices(element, lst):
    indices = []
    for i in range(len(lst)):
        if lst[i] == element:
            indices.append(i)
    return indices


print("Birch 5 clusters start") # accuract 6 %

labels = Birch(n_clusters=5).fit_predict(X)
unique_labels, counts_labels = np.unique(labels, return_counts=True)

distripution_matrix = np.zeros((5, 7))
for label in unique_labels: # looping on cluster
    locations_of_label = get_indices(label, labels) # get locations of cluster 0 in labels
    attacks_types_in_label = attack_type_labels[locations_of_label] # get rows of attack type responding thes locations
    unique, counts = np.unique(attacks_types_in_label, return_counts=True)
    for count,typex in enumerate(unique):
        distripution_matrix[label][typex]= counts[count]

print("Birch distripution_matrix:\n",distripution_matrix.astype(int))

# distripution_matrix: 
#  [[   2    0    0    0    0    0    0]
#  [ 140    4 1590    8    8 5299 5718]
#  [   4    0    0    0    0    0    0]
#  [   1    0    0    0    0    0    0]
#  [   1    0    0    0    0    0    0]]

print("Birch 5 clusters end \n\n") # 

# exit()


print("AgglomerativeClustering 5 clusters start") # accuract 6 %

labels = AgglomerativeClustering(n_clusters=5,linkage ='single').fit_predict(X)

unique_labels, counts_labels = np.unique(labels, return_counts=True)

distripution_matrix = np.zeros((5, 7))
for label in unique_labels: # looping on cluster
    locations_of_label = get_indices(label, labels) # get locations of cluster 0 in labels
    attacks_types_in_label = attack_type_labels[locations_of_label] # get rows of attack type responding thes locations
    unique, counts = np.unique(attacks_types_in_label, return_counts=True)
    for count,typex in enumerate(unique):
        distripution_matrix[label][typex]= counts[count]

print("Agglomerative distripution_matrix:\n",distripution_matrix.astype(int))
print("Agglomerative Clustering 5 clusters end") # 

# distripution_matrix: 
#  [[ 144    4 1590    8    8 5299 5718]
#  [   1    0    0    0    0    0    0]
#  [   1    0    0    0    0    0    0]
#  [   1    0    0    0    0    0    0]
#  [   1    0    0    0    0    0    0]]

print("AgglomerativeClustering 5 clusters end\n\n") # 

# exit()

# print("SpectralClustering 2 clusters start") #  long time - stopped

# from sklearn.cluster import SpectralClustering
# import numpy as np

# labels = SpectralClustering(n_clusters=2,assign_labels='discretize',random_state=0).fit_predict(X)
# unique, counts = np.unique(labels, return_counts=True)
# print("unique",unique)
# print("counts",counts)
# Grouped_Benign_count = 0
# Grouped_Malignant_count = 0
# for i in range(len(labels)):
#     if labels[i] == 0:
#         if df.loc[i,'attack'] == "Benign" :
#             Grouped_Benign_count += 1
#         else:
#             Grouped_Malignant_count +=1

# print(Grouped_Benign_count)
# print(Grouped_Malignant_count)

# if min(counts) < len(df_Benign_important):
#     print("MiniBatchKMeans 2 clusters Accuracy = ", min(counts) / len(df_Benign_important) *100 , "%" )
# else:
#     print("MiniBatchKMeans 2 clusters Accuracy = ", len(df_Benign_important) / min(counts)  *100 , "%" )

# print("MiniBatchKMeans 2 clusters end") # 

# exit()

print("MiniBatchKMeans 5 clusters start") # accuract 6 %

labels = MiniBatchKMeans(n_clusters=5,tol=.0001, random_state=0).fit_predict(X)
unique_labels, counts_labels = np.unique(labels, return_counts=True)

distripution_matrix = np.zeros((5, 7))
for label in unique_labels: # looping on cluster
    locations_of_label = get_indices(label, labels) # get locations of cluster 0 in labels
    attacks_types_in_label = attack_type_labels[locations_of_label] # get rows of attack type responding thes locations
    unique, counts = np.unique(attacks_types_in_label, return_counts=True)
    for count,typex in enumerate(unique):
        distripution_matrix[label][typex]= counts[count]

print("MiniBatchKMeans distripution_matrix:\n",distripution_matrix.astype(int))
print("MiniBatchKMeans Clustering 5 clusters end") # 

print("MiniBatchKMeans 5 clusters end \n\n") # 

#  [[  39    0    1    0    0 2033 1624]
#  [  47    0 1589    0    4    0    0]
#  [   5    0    0    0    0    0 2374]
#  [  51    1    0    8    4 2251    0]
#  [   6    3    0    0    0 1015 1720]]

# exit()

print("Kmean 5 clusters start") # accuracy = 2.7 %

labels = KMeans(n_clusters=5,tol=.00001, random_state=1, algorithm="elkan").fit_predict(X)
unique_labels, counts_labels = np.unique(labels, return_counts=True)

distripution_matrix = np.zeros((5, 7))
for label in unique_labels: # looping on cluster
    locations_of_label = get_indices(label, labels) # get locations of cluster 0 in labels
    attacks_types_in_label = attack_type_labels[locations_of_label] # get rows of attack type responding thes locations
    unique, counts = np.unique(attacks_types_in_label, return_counts=True)
    for count,typex in enumerate(unique):
        distripution_matrix[label][typex]= counts[count]

print("Kmean distripution_matrix:\n",distripution_matrix.astype(int))
print("Kmean Clustering 5 clusters end") # 

#  [[ 140    4 1590    8    8 5299 5718]
#  [   1    0    0    0    0    0    0]
#  [   2    0    0    0    0    0    0]
#  [   1    0    0    0    0    0    0]
#  [   4    0    0    0    0    0    0]]

print("Kmean 5 clusters End") # 


