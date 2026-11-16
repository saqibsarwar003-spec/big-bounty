'use strict';

function normEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function validEmail(value) {
  const email = normEmail(value);
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

module.exports = { normEmail, validEmail };
