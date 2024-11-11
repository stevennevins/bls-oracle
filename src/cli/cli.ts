#!/usr/bin/env node
const { program } = require('commander');
const { getPubkeyCommand } = require('./commands/getPubkey');
const { getAggPubkeyCommand } = require('./commands/getAggPubkey');
const { hashMessageCommand } = require('./commands/hashMessage');
const { signMessageCommand } = require('./commands/signMessage')
const { signAggMessageCommand } = require('./commands/signAggMessage')

program.addCommand(getPubkeyCommand);
program.addCommand(getAggPubkeyCommand);
program.addCommand(hashMessageCommand);
program.addCommand(signMessageCommand);
program.addCommand(signAggMessageCommand);

program.parse(process.argv);