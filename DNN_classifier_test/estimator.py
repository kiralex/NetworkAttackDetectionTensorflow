#!/bin/python3

import tensorflow as tf
import argparse
from termcolor import colored, cprint

import data

parser = argparse.ArgumentParser()
parser.add_argument('--batch_size', default=100, type=int, help='batch size')
parser.add_argument(
    '--train_steps', default=1000, type=int, help='number of training steps')


def main(argv):

    args = parser.parse_args(argv[1:])

    (train_x, train_y), (test_x, test_y) = data.load_data()

    categorial_column = tf.feature_column.categorical_column_with_vocabulary_list
    numeric_column = tf.feature_column.numeric_column
    indicator_column = tf.feature_column.indicator_column

    # get features columns
    my_feature_columns = [
        indicator_column(
            categorial_column(key=data.COL1_NAME, vocabulary_list=["one", "zero"])
        ),
        indicator_column(
            categorial_column(key=data.COL2_NAME, vocabulary_list=["one", "zero"])
        )
    ]

    classifier = tf.estimator.DNNClassifier(
        feature_columns=my_feature_columns,
        # Two hidden layers of 10 nodes each.
        hidden_units=[5, 5, 5],
        # The model must choose between 2 classes.
        label_vocabulary=["chien", "chat"],
        n_classes=2)

    cprint(test_x, 'red')
    cprint(test_y, 'blue')


    # Train the Model.
    classifier.train(
        input_fn=lambda: data.train_input_fn(
            train_x, train_y, args.batch_size),
        steps=args.train_steps)

    # Evaluate the model.
    eval_result = classifier.evaluate(
        input_fn=lambda: data.eval_input_fn(test_x, test_y, args.batch_size))

    print('\nTest set accuracy: {accuracy:0.3f}\n'.format(**eval_result))


if __name__ == '__main__':
    tf.logging.set_verbosity(tf.logging.WARN)
    tf.app.run(main)
