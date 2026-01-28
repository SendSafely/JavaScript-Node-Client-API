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
    this.eof = false;
    this.data = [];
    this.tempSize = 0;

    this.init = function() {
        return new Promise(function(resolve) {
            fs.stat(myself.filePath, (err, stats) => {
                if (err) {
                    throw new Error('FileUtil: File does not exist, ' + myself.filePath);
                } else {
                    myself.readableStream = fs.createReadStream(myself.filePath);
                    myself.readableStream.on('readable', function () {
                        if (myself.waitingForRead) {
                            processChunk();
                        }
                    });

                    myself.readableStream.on('end', function() {
                        // done reading file
                        myself.eof = true;
                        if (myself.waitingForRead) {
                            // Handle timing edge case where 'end' fires while a read is pending
                            processChunk();
                        }
                    });

                    const totalParts = stats.size === 0 ? 1 : Math.ceil(stats.size / myself.SEGMENT_SIZE);

                    resolve({
                        name: path.basename(myself.filePath),
                        size: stats.size,
                        totalParts: totalParts,
                    });
                }
            });

        });
    }

    this.read = function() {
        if (myself.eof && myself.tempSize === 0) {
            return;
        }

        myself.waitingForRead = true;
        processChunk();
    }

    function processChunk() {
        let chunk;
        while ((chunk = myself.readableStream.read()) !== null) { // Completely drain the stream's internal buffer
            myself.data.push(new Uint8Array(chunk));
            myself.tempSize += chunk.length;
        }

        if (myself.tempSize >= myself.SEGMENT_SIZE || myself.eof) {
            if (myself.tempSize > 0) {
                // We have a full segment
                const buf = concatenate(myself.data);
                const seg = buf.slice(0, myself.SEGMENT_SIZE);
                const remainder = buf.slice(myself.SEGMENT_SIZE);
                myself.data = remainder.length > 0 ? [remainder] : [];
                myself.tempSize = remainder.length;
                myself.callback({data: seg, complete: myself.eof && myself.tempSize === 0});
            } else {
                // Emit an empty final segment to signal completion & handles empty files
                myself.callback({data: new Uint8Array(0), complete: true});
            }
            myself.waitingForRead = false;
        }
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