import pandas as pd 
import numpy as np
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.model_selection import ParameterGrid
from sklearn.cluster import KMeans
from sklearn import metrics
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.ensemble import IsolationForest
from sklearn import svm
from sklearn.cluster import KMeans
from sklearn.covariance import EllipticEnvelope
from pyod.models.abod import ABOD
from sklearn.covariance import EmpiricalCovariance, MinCovDet
from sklearn.cluster import SpectralClustering

df = pd.read_csv('multi/_Joined In depth packet analysis.csv')
df.fillna(0, inplace=True)
# print(type(df))
# print(df.head(5))

print('The shape of our features is:', df.shape)

# Descriptive statistics for each column
# print(df.describe())

le_Protocol = LabelEncoder()
label_Protocol = le_Protocol.fit_transform(df['Protocol'])
df.drop("Protocol", axis=1, inplace=True)
df["Protocol"] = label_Protocol

# le_attack_type = LabelEncoder()
# label_attack_type = le_attack_type.fit_transform(df['attack type'])
# df.drop("attack type", axis=1, inplace=True)
# df["attack type"] = label_attack_type

le_isserver = LabelEncoder()
label_isserver = le_isserver.fit_transform(df['IsServer'])
df.drop("IsServer", axis=1, inplace=True)
df["IsServer"] = label_isserver

df['attack'].replace(0, 'Benign',inplace=True)
df['attack'].replace(1, 'Malignant',inplace=True)

# df_important= df.loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","attack"]]
df_Benign_important = df.loc[df['attack'] == 'Benign'].loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","IOT_Respond_401"]]
df_Malignant_important = df.loc[df['attack'] == 'Malignant'].loc[: , ["Protocol","No_of_received_packets_per_minutes","No_of_sent_packets_per_minutes","Flow_volume","IsServer","IOT_Respond_401"]]

print("Benign size: ", len(df_Benign_important))
print("Malignant size: ", len(df_Malignant_important))
print( "positive is Benign , negative is Malignant" )

np_Benign_important = np.array(df_Benign_important)
np_Malignant_important = np.array(df_Malignant_important)

print("Angle-Based Outlier Detection Start") # very slow

abod_model = ABOD(method="fast",n_neighbors=4,contamination=.1)
# (method="default",n_neighbors=2,5,10)
# TP =  15
# TN =  12626
# FP =  133
# FN =  1
# method="default",n_neighbors=2,contamination=.2
# TP =  30
# TN =  12541
# FP =  118
# FN =  86
# Angle-Based Outlier Detection Accuracy:  98.40313111545989 %
# method="default",n_neighbors=2,contamination=.3
# TP =  45
# TN =  10841
# FP =  103
# FN =  1786
# Angle-Based Outlier Detection Accuracy:  85.21330724070451 %
# method="default",n_neighbors=2,contamination=.4
# TP =  59
# TN =  7
# FP =  89
# FN =  12620
# Angle-Based Outlier Detection Accuracy:  0.5166340508806262 %
abod_model.fit(np_Benign_important)
is_inlier_Benign = abod_model.predict(np_Benign_important)
is_inlier_Malignant = abod_model.predict(np_Malignant_important)

# print((is_inlier_Benign))
# print((is_inlier_Malignant))

print(len(is_inlier_Benign))
print(len(is_inlier_Malignant))

TP = np.count_nonzero(is_inlier_Benign == True)
TN = np.count_nonzero(is_inlier_Malignant == False)
FP = np.count_nonzero(is_inlier_Benign == False)
FN = np.count_nonzero(is_inlier_Malignant == True)
print("TP = ", TP )
print("TN = ", TN)
print("FP = ", FP )
print("FN = ", FN )
print("Angle-Based Outlier Detection Accuracy: " , (TP+TN)/(len(df_Benign_important)+len(df_Malignant_important)) *100 ,"%" )

print("Angle-Based Outlier Detection End\n\n\n")

exit()

print("EllipticEnvelope Start") # bad results

EllipticEnvelope_model = EllipticEnvelope(contamination=0.3,random_state=6)
EllipticEnvelope_model.fit(np_Benign_important)
is_inlier_Benign = EllipticEnvelope_model.predict(np_Benign_important)
is_inlier_Malignant = EllipticEnvelope_model.predict(np_Malignant_important)

# print((is_inlier_Benign))
# print((is_inlier_Malignant))

print(len(is_inlier_Benign))
print(len(is_inlier_Malignant))

TP = np.count_nonzero(is_inlier_Benign == 1)
TN = np.count_nonzero(is_inlier_Malignant == -1)
FP = np.count_nonzero(is_inlier_Benign == -1)
FN = np.count_nonzero(is_inlier_Malignant == 1)
print("TP = ", TP )
print("TN = ", TN)
print("FP = ", FP )
print("FN = ", FN )
print("EllipticEnvelope Accuracy: " , (TP+TN)/(len(df_Benign_important)+len(df_Malignant_important)) *100 ,"%" )

print("EllipticEnvelope End\n\n\n")

exit()

print("MinCovDet Start")

MinCovDet_model = EllipticEnvelope(contamination=0.3, random_state=6)
MinCovDet_model.fit(np_Benign_important)
is_inlier_Benign = MinCovDet_model.predict(np_Benign_important)
is_inlier_Malignant = MinCovDet_model.predict(np_Malignant_important)

# print((is_inlier_Benign))
# print((is_inlier_Malignant))

print(len(is_inlier_Benign))
print(len(is_inlier_Malignant))

TP = np.count_nonzero(is_inlier_Benign == 1)
TN = np.count_nonzero(is_inlier_Malignant == -1)
FP = np.count_nonzero(is_inlier_Benign == -1)
FN = np.count_nonzero(is_inlier_Malignant == 1)
print("TP = ", TP )
print("TN = ", TN)
print("FP = ", FP )
print("FN = ", FN )
print("MinCovDet Accuracy: " , (TP+TN)/(len(df_Benign_important)+len(df_Malignant_important)) *100 ,"%" )

print("MinCovDet End\n\n\n")

exit()


print("OneClassSVM Start")

OneClassSVM_model = svm.OneClassSVM(kernel='rbf',gamma=.2)
OneClassSVM_model.fit(np_Benign_important)
is_inlier_Benign = OneClassSVM_model.predict(np_Benign_important)
is_inlier_Malignant = OneClassSVM_model.predict(np_Malignant_important)

# print((is_inlier_Benign))
# print((is_inlier_Malignant))

print(len(is_inlier_Benign))
print(len(is_inlier_Malignant))

TP = np.count_nonzero(is_inlier_Benign == 1)
TN = np.count_nonzero(is_inlier_Malignant == -1)
FP = np.count_nonzero(is_inlier_Benign == -1)
FN = np.count_nonzero(is_inlier_Malignant == 1)
print("TP = ", TP )
print("TN = ", TN)
print("FP = ", FP )
print("FN = ", FN )
print("OneClassSVM Accuracy: " , (TP+TN)/(len(df_Benign_important)+len(df_Malignant_important)) *100 ,"%" )

print("OneClassSVM End\n\n\n")

exit()

print("IsolationForest Start")

IsolationForest_model=IsolationForest(n_estimators=5, max_samples=10,max_features=6,random_state=5,contamination=.34)
IsolationForest_model.fit(np_Benign_important)
is_inlier_Benign = IsolationForest_model.predict(np_Benign_important)
is_inlier_Malignant = IsolationForest_model.predict(np_Malignant_important)

# print((is_inlier_Benign))
# print((is_inlier_Malignant))

print(len(is_inlier_Benign))
print(len(is_inlier_Malignant))

TP = np.count_nonzero(is_inlier_Benign == 1)
TN = np.count_nonzero(is_inlier_Malignant == -1)
FP = np.count_nonzero(is_inlier_Benign == -1)
FN = np.count_nonzero(is_inlier_Malignant == 1)
print("TP = ", TP )
print("TN = ", TN)
print("FP = ", FP )
print("FN = ", FN )
print("IsolationForest Accuracy: " , (TP+TN)/(len(df_Benign_important)+len(df_Malignant_important)) *100 ,"%" )

print("IsolationForest End\n\n\n")

exit()


print("LocalOutlierFactor Start")

clf_model = LocalOutlierFactor(n_neighbors=2,novelty=True)

clf_model.fit(np_Benign_important)
is_inlier_Benign = clf_model.predict(np_Benign_important)
is_inlier_Malignant = clf_model.predict(np_Malignant_important)

# print(len(is_inlier_Benign))
# print(len(is_inlier_Malignant))

# print(is_inlier_Benign.sum())
# print(is_inlier_Malignant.sum())

TP = np.count_nonzero(is_inlier_Benign == 1)
TN = np.count_nonzero(is_inlier_Malignant == -1)
FP = np.count_nonzero(is_inlier_Benign == -1)
FN = np.count_nonzero(is_inlier_Malignant == 1)
print("TP = ", TP )
print("TN = ", TN)
print("FP = ", FP )
print("FN = ", FN )
print("LocalOutlierFactor Accuracy: " , (TP+TN)/(len(df_Benign_important)+len(df_Malignant_important)) *100 ,"%" )

print("LocalOutlierFactor End\n\n\n")

exit()

print("KMeans Start ") # bad results 

KMeans_model = KMeans(n_clusters = 1)
KMeansfit = KMeans_model.fit(np_Benign_important)
center = KMeansfit.cluster_centers_
# print(center)
distances_Benign = np.sum(np.sqrt((np_Benign_important - center)**2), axis=1)
# print(len(distances_Benign))
# print(np.min(distances_Benign))
# print(np.mean(distances_Benign))
# print(np.max(distances_Benign))
distances_Malignant = np.sum(np.sqrt((np_Malignant_important - center)**2), axis=1)
# print(len(distances_Malignant))
# print(np.min(distances_Malignant))
# print(np.mean(distances_Malignant))
# print(np.max(distances_Malignant))

threashold = 42500

TP = np.count_nonzero(distances_Benign > threashold)
TN = np.count_nonzero(distances_Malignant < threashold)
FP = np.count_nonzero(distances_Benign < threashold)
FN = np.count_nonzero(distances_Malignant > threashold)

print("TP = ", TP )
print("TN = ", TN )
print("FP = ", FP )
print("FN = ", FN )
print("KMeans Accuracy: " , (TP+TN)/(len(df_Benign_important)+len(df_Malignant_important)) *100 ,"%" )


# print(distances_Benign)


# TP = np.count_nonzero(is_inlier_Benign == 1)
# TN = np.count_nonzero(is_inlier_Malignant == -1)
# FP = np.count_nonzero(is_inlier_Benign == -1)
# FN = np.count_nonzero(is_inlier_Malignant == 1)
# print("TP = ", TP )
# print("TN = ", TN)
# print("FP = ", FP )
# print("FN = ", FN )
# print("KMeans Accuracy: " , (TP+TN)/(len(df_Benign_important)+len(df_Malignant_important)) *100 ,"%" )

print("KMeans End\n\n\n")

exit()





# print(df_Benign_important)