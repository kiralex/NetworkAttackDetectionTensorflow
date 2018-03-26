#!/bin/python3

import tensorflow as tf
import pandas as pd
import numpy as np
from termcolor import colored, cprint

TRAIN_URL = "./out.csv"
TEST_URL = "./out.csv"

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


def parse_label_column(label_string_tensor):

    # Build a Hash Table inside the graph
    table = tf.contrib.lookup.index_table_from_tensor(tf.constant(LABELS))

    # Use the hash table to convert string labels to ints and one-hot encode
    return table.lookup(label_string_tensor)


def load_data(label_name='class'):
    """Parses the csv file in TRAIN_URL and TEST_URL."""

    # # Create a local copy of the training set.
    # train_path = tf.keras.utils.get_file(fname=TRAIN_URL.split('/')[-1],
    #                                      origin=TRAIN_URL)

    # Not using network !
    train_path = TRAIN_URL

    # Parse the local CSV file.
    train = pd.read_csv(filepath_or_buffer=train_path,
                        sep=";",
                        names=CSV_COLUMN_NAMES,  # list of column names
                        header=None,  # as the first line does not contain column names
                        dtype={'class': np.object}
                        )

    # 1. Assign the DataFrame's labels (the right-most column) to train_label.
    # 2. Delete (pop) the labels from the DataFrame.
    # 3. Assign the remainder of the DataFrame to train_features
    train_features, train_label = train, train[label_name]

    # Apply the preceding logic to the test set.
    # test_path = tf.keras.utils.get_file(TEST_URL.split('/')[-1], TEST_URL)
    test_path = TRAIN_URL
    test = pd.read_csv(test_path, sep=";", names=CSV_COLUMN_NAMES, header=None)

    test_label = test[label_name]
    # remove the class
    test_features = test.drop('class', axis='columns')

    # Return four DataFrames.
    return (train_features, train_label), (test_features, test_label)


def train_input_fn(features, labels, batch_size):
    """An input function for training"""

    # Convert the inputs to a Dataset.
    dataset = tf.data.Dataset.from_tensor_slices((dict(features), labels))

    # Shuffle, repeat, and batch the examples.
    dataset = dataset.shuffle(1000).repeat().batch(batch_size)

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
