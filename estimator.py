#!/bin/python3

import tensorflow as tf
import argparse
from termcolor import colored, cprint

import data

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--batch-size', default=1000, type=int, help='batch size')
    parser.add_argument(
        '--train-steps', default=10000, type=int, help='number of training steps')
    parser.add_argument(
        '--train-file',type=str, help='training file', required=True)
    parser.add_argument(
        '--test-file',type=str, help='test file', required=True)

    args = parser.parse_args(argv[1:])

    data.TRAIN_URL = args.train_file
    data.TEST_URL = args.test_file

    (train_x, train_y), (test_x, test_y) = data.load_data()

    # cprint(test_x, 'red')
    # cprint(test_y, 'blue')

    indicator_column = tf.feature_column.embedding_column
    numeric_column = tf.feature_column.numeric_column
    categorical_column_with_hash_bucket = tf.feature_column.categorical_column_with_hash_bucket
    embedding_column = tf.feature_column.embedding_column

    # get features columns
    my_feature_columns = [
        numeric_column(key=data.TIMESTAMP_NAME),
        embedding_column(
            categorical_column_with_hash_bucket(
                key=data.SOURCE_IP_NAME,
                hash_bucket_size=10000),
            50
        ),
        embedding_column(
            categorical_column_with_hash_bucket(
                key=data.DESTINATION_IP_NAME,
                hash_bucket_size=10000),
            50
        ),
        numeric_column(key=data.SOURCE_PORT_NAME),
        numeric_column(key=data.DESTINATION_PORT_NAME),
        embedding_column(
            categorical_column_with_hash_bucket(
                key=data.FLAGS_NAME,
                hash_bucket_size=20),
            50
        ),
        numeric_column(key=data.IDENTIFICATION_NAME),
        embedding_column(
            categorical_column_with_hash_bucket(
                key=data.DATA_NAME,
                hash_bucket_size=10000),
            50
        )
    ]

    classifier = tf.estimator.DNNClassifier(
        feature_columns=my_feature_columns,
        # Two hidden layers of 10 nodes each.
        hidden_units=[10, 10, 10],
        # The model must choose between 2 classes.
        label_vocabulary=data.LABELS,
        n_classes=2,
        model_dir="model/DNN/Giga"
    )

    # Train the Model.
    classifier.train(
        input_fn=lambda: data.train_input_fn(
            train_x, train_y, args.batch_size),
        steps=args.train_steps)

    # Evaluate the model.
    eval_result = classifier.evaluate(
        input_fn=lambda: data.eval_input_fn(train_x, train_y, args.batch_size))

    print('\nTest set accuracy with same data as training) : {accuracy:0.3f}\n'.format(
        **eval_result))

    # Evaluate the model.
    eval_result = classifier.evaluate(
        input_fn=lambda: data.eval_input_fn(test_x, test_y, args.batch_size))

    print('\nTest set accuracy (with other data): {accuracy:0.3f}\n'.format(
        **eval_result))


if __name__ == '__main__':
    tf.logging.set_verbosity(tf.logging.WARN)

    tf.app.run()