#!/bin/python3

import tensorflow as tf
import pandas as pd
import numpy as np
from termcolor import colored, cprint

TEST_URL = "./mySuperCSV.csv"
TRAIN_URL = "./mySuperCSV.csv"

TIMESTAMP_NAME = "timestamp"
SOURCE_IP_NAME = "source_ip"
DESTINATION_IP_NAME = "destination_ip"
SOURCE_PORT_NAME = "source_port"
DESTINATION_PORT_NAME = "destination_port"
FLAGS_NAME = "flags"
IDENTIFICATION_NAME = "identification"
DATA_NAME = "data"
CLASS_NAME = "class"

CSV_COLUMN_NAMES = [TIMESTAMP_NAME, SOURCE_IP_NAME, DESTINATION_IP_NAME,
                    SOURCE_PORT_NAME, DESTINATION_PORT_NAME, FLAGS_NAME,
                    IDENTIFICATION_NAME, DATA_NAME, CLASS_NAME]

LABELS = ["attack", "safe-packet"]


def load_data(label_name='class'):
    """Parses the csv file in TRAIN_URL and TEST_URL."""
    train_path = TRAIN_URL

    # Parse the local CSV file.
    train = pd.read_csv(filepath_or_buffer=train_path,
                        sep=",",
                        names=CSV_COLUMN_NAMES,  # list of column names
                        header=0,
                        )

    train.fillna("", inplace=True)

    # Assign the DataFrame's labels (the right-most column) to train_label.
    # & Delete (pop) the labels from the DataFrame.
    # &Assign the remainder of the DataFrame to train_features
    train_features, train_label = train, train[label_name]
    train_features = train_features.drop('class', axis='columns')

    # Apply the preceding logic to the test set.
    test_path = TEST_URL
    test = pd.read_csv(filepath_or_buffer=test_path,
                       sep=",",
                       names=CSV_COLUMN_NAMES,  # list of column names
                       header=0, 
                       )

    test.fillna("", inplace=True)

    test_label = test[label_name]
    test_features = test.drop('class', axis='columns')

    # Return four DataFrames.
    return (train_features, train_label), (test_features, test_label)


def train_input_fn(features, labels, batch_size):
    """An input function for training"""
    # Convert the inputs to a Dataset.
    dataset = tf.data.Dataset.from_tensor_slices((dict(features), labels))

    # Shuffle, repeat, and batch the examples.
    dataset = dataset.repeat().batch(batch_size)

    # Return the dataset.
    return dataset


def eval_input_fn(features, labels, batch_size):
    """An input function for evaluation or prediction"""
    features = dict(features)
    if labels is None:
        # No labels, use only features.
        inputs = features
    else:
        inputs = (features, labels)

    # Convert the inputs to a Dataset.
    dataset = tf.data.Dataset.from_tensor_slices(inputs)

    # Batch the examples
    assert batch_size is not None, "batch_size must not be None"
    dataset = dataset.batch(batch_size)

    # Return the dataset.
    return dataset
