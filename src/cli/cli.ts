#!/usr/bin/env node
const { program } = require('commander');
const { getPubkey } = require('./commands/getPubkey');
const { getPubkeyG1 } = require('./commands/getPubkeyG1');
const { getAggPubkey } = require('./commands/getAggPubkey');
const { hashMessage } = require('./commands/hashMessage');
const { sign } = require('./commands/signMessage')
const { signAggMessage } = require('./commands/signAggMessage')

program.addCommand(getPubkey);
program.addCommand(getPubkeyG1);
program.addCommand(getAggPubkey);
program.addCommand(hashMessage);
program.addCommand(sign);
program.addCommand(signAggMessage);

program.parse(process.argv);