
#Step 1 - Import library

import matplotlib.pyplot as plt
import numpy as np
from sklearn import datasets
import tensorflow.compat.v1 as tf
#Step 2 - Load the dataset

tf.disable_v2_behavior()
iris_data = datasets.load_iris()
#print(iris_data)
x_variable = np.array([x[0:4] for x in iris_data.data])
#print(x_variable)

y_variable = np.array(iris_data.target)
#print(y_variable)
#print(len(y_variable))


#Step 3 - Perform one hot encoding
y_variable = np.eye(len(set(y_variable)))[y_variable]
#print(y_variable)


# #Step 4 - Normalize the data

x_variable = (x_variable - x_variable.min(0)) / x_variable.ptp(0)
#print(x_variable)
#Step 5 - Split the data in train and test

np.random.seed(59)
train_data = np.random.choice(len(x_variable), round(len(x_variable) * 0.8),replace=False)
test_data =np.array(list(set(range(len(x_variable))) - set(train_data)))

x_variable_train = x_variable[train_data]
x_variable_test = x_variable[test_data]
y_variable_train = y_variable[train_data]
y_variable_test = y_variable[test_data]

#Step 6 - Define features

features = len(x_variable_train[0])
k = 5

x_new_train = tf.compat.v1.placeholder(shape=[None, features], dtype=tf.float32)
y_new_train = tf.compat.v1.placeholder(shape=[None, len(y_variable[0])], dtype=tf.float32)
x_new_test = tf.compat.v1.placeholder(shape=[None, features], dtype=tf.float32)

#Step 7 - Define manhattan distance and nearest k points

# manhattan distance
manht_distance = tf.reduce_sum(tf.abs(tf.subtract(x_new_train, tf.expand_dims(x_new_test, 1))), axis=2)

# nearest k points
_, top_k_indices = tf.nn.top_k(tf.negative(manht_distance), k=k)
top_k_labels = tf.gather(y_new_train, top_k_indices)

predictions_sumup = tf.reduce_sum(top_k_labels, axis=1)
make_prediction = tf.argmax(predictions_sumup, axis=1)

#Step 8 - Training and evaluation

sess = tf.compat.v1.Session()
outcome_prediction = sess.run(make_prediction, feed_dict={x_new_train: x_variable_train,
                               x_new_test: x_variable_test,
                               y_new_train: y_variable_train})


accuracy = 0
for pred, actual in zip(outcome_prediction, y_variable_test):
    if pred == np.argmax(actual):
        accuracy += 1

print("This is final output:",accuracy / len(outcome_prediction))

#This is final output: 0.9666666666666667
