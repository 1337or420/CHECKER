'use strict';
// Checker module — delegates to the shared credential engine (kind 'check').
const bruter = require('./bruter');

async function checkTask(task, emit) {
    return bruter.run(task, emit, 'check');
}

module.exports = { checkTask };
