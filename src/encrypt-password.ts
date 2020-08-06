/**
 * @file encrypt-password.js - Convenient password encryption function using bcrypt-pbkdf.
 */

import { env } from 'process';

import { pbkdf } from 'bcrypt-pbkdf';


const minSaltLengh = 8;

(function validateSaltVariable(SALT) {

 if (SALT === undefined) return;
 if (typeof SALT !== 'string' || SALT.length < minSaltLengh) {
    throw new TypeError(
      `The SALT environment variable must be at least ${minSaltLengh} characters long.`
    );
  }
})(env.SALT);


/**
 * Encrypts a password using bcrypt.
 * 
 * - The salt can be specified via either the SALT environment variable or the
 * `salt` option.
 *
 * - For security this function does not return a string but a mutable buffer,
 * so that you can immediately clear it after use, for example `buffer.fill(0)`.
 *
 * @param {string} password
 *
 * @param {object} [options]
 *
 * @param {number} [options.outputLength = 32] - The length the generated
 * encrypted output should be.
 *
 * @param {number} [options.numberOfRounds = 1] - The number of rounds of the
 * PBKDF encryption algorithm to perform.
 *
 * @param {string} [options.salt] - The salt to use.
 * - Defaults to the value of the SALT environment variable.
 * - Throws a TypeError if no valid salt value was found.
 *
 * @returns {Buffer}
 */
export default function encryptPassword(
  password: string,
  {
    numberOfRounds = 1,
    outputLength = 32,
    salt = env.SALT,
  } = {}
) {
  if (typeof password !== 'string') {
    throw new TypeError('Argument `password` must be a string.');
  }

  if (!Number.isInteger(numberOfRounds) || numberOfRounds < 1) {
    throw new TypeError(
      'If specified, option `numberOfRounds` must be a positive integer.'
    );
  }

  if (!Number.isInteger(outputLength) || outputLength < 1) {
    throw new TypeError(
      'If specified, option `outputLength` must be a positive integer.'
    );
  }

  if (typeof salt !== 'string') {
    throw new TypeError('Argument `salt` must be a string.');
  }
  if (salt.length < minSaltLengh) {
    throw new TypeError(`Argument \`salt\` must be at least ${minSaltLengh} characters long.`);
  }

  const buffer = Buffer.from(password);
  /*
   * Note that `buffer.length` is not the same as `password.length` since
   *   passwords may contain non-ASCII characters.
   */
  const bufferLength = buffer.length;
  const saltBuffer = Buffer.from(salt);
  const saltBufferLength = saltBuffer.length;
  const outputBuffer = Buffer.alloc(outputLength);

  pbkdf(
    buffer,
    bufferLength,
    saltBuffer,
    saltBufferLength,
    outputBuffer,
    outputLength,
    numberOfRounds
  );
  return outputBuffer;
}

// Workaround
if (typeof module === "object") module.exports = encryptPassword;
