const fs = require('fs');
const path = require("path");

function FileUtil(param) {

    if(param === undefined || typeof param !== 'object') {
        throw new Error('FileUtil: Invalid parameters');
    }

    if(!param.hasOwnProperty('filePath')) {
        throw new Error('FileUtil: filePath is needed');
    }

    if(!param.hasOwnProperty('callback')) {
        throw new Error('FileUtil: callback is needed');
    }

    if(param.hasOwnProperty('callback') && typeof param.callback !== 'function') {
        throw new Error('FileUtil: callback must be a function');
    }

    let myself = this;
    this.SEGMENT_SIZE = 2621440;
    this.filePath = param.filePath;
    this.callback = param.callback;
    this.file = {size: 0, name: '', totalParts: 0};
    this.readableStream = fs.createReadStream(myself.filePath);
    this.reading = false;
    this.eof = false;
    this.data = [];
    this.tempSize = 0;

    this.init = function() {
        return new Promise(function(resolve) {
            fs.stat(myself.filePath, (err, stats) => {
                if (err) {
                    throw new Error('FileUtil: File does not exist, ' + myself.filePath);
                } else {
                    myself.file.size = stats.size;
                    myself.file.name =  path.basename(myself.filePath);

                    if(myself.file.size > (myself.SEGMENT_SIZE/4)) {
                        myself.file.totalParts = Math.ceil((myself.file.size-(myself.SEGMENT_SIZE/4))/myself.SEGMENT_SIZE);
                    } else {
                        myself.file.totalParts = 1;
                    }

                    resolve(myself.file);

                    myself.readableStream.on('readable', function() {
                        // keep reading chunk until it reaches SEGMENT_SIZE
                        if(myself.reading && !myself.eof) {
                            processChunk();
                        }
                    });

                    myself.readableStream.on('end', function() {
                        // done reading file
                        if(!myself.eof) {
                            myself.eof = true;
                            callback(true);
                        }
                    });
                }
            });

        });
    }

    this.read = function() {
        if(!myself.reading && !myself.eof) {
            myself.reading = true;
            processChunk();
        }
    }

    function processChunk() {
        if(myself.tempSize === myself.SEGMENT_SIZE) {
            // callback when data size reaches SEGMENT_SIZE
            callback(false);
        } else {
            let chunk = myself.readableStream.read();
            if(chunk !== null) {
                myself.data.push(new Uint8Array(chunk));
                myself.tempSize += chunk.length;
            }
        }
    }

    function callback(isComplete) {
        myself.tempSize = 0;
        myself.reading = false;
        myself.callback({data: concatenate(myself.data), complete: isComplete});
        myself.data = [];
    }

    function concatenate(arrays) {
        var totalLength = arrays.reduce(function(total, arr) {
            return total + arr.length
        }, 0);
        var result = new Uint8Array(totalLength);
        arrays.reduce(function(offset, arr){
            result.set(arr, offset);
            return offset + arr.length;
        }, 0);
        return result;
    }
}

module.exports = {FileUtil};