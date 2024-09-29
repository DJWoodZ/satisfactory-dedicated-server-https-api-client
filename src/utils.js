const utils = {
  /**
   * Deep merge multiple objects into one.
   * @param {...any} objects The objects to merge.
   * @returns {Object} The merged object.
   */
  deepMerge: (...objects) => {
    // check is no arguments passed
    if (!objects.length) {
      throw new Error('No objects provided for merging.');
    }

    const result = {};

    const seenObjects = new WeakSet();

    const mergeObjects = (...objs) => {
      objs.forEach((obj) => {
        if (typeof obj !== 'object' || obj === null) {
          // skip non-objects and null values
          return;
        }

        // mark the current object as seen
        seenObjects.add(obj);

        Object.keys(obj).forEach((key) => {
          const value = obj[key];

          if (value !== undefined && value !== null
            && (Array.isArray(value)
            || (typeof value === 'object' && Object.prototype.isPrototypeOf.call(Object.getPrototypeOf(value), Object)))) {
            // skip already seen object to avoid infinite loop
            if (seenObjects.has(value)) return;

            // value is either an object or an array, so proceed with merging
            if (Array.isArray(value)) {
              // merge arrays
              result[key] = [...(result[key] || []), ...value];
            } else {
              // merge objects
              result[key] = utils.deepMerge(result[key], value);
            }
          } else {
            // value is not an object or array, so simply assign it to the result
            result[key] = value;
          }
        });
      });
    };

    mergeObjects(...objects);

    return result;
  },
};

module.exports = utils;
