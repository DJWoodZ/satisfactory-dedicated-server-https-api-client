const utils = require('../src/utils');

describe('utils', () => {
  it('should be able to merge two objects', () => {
    const result = utils.deepMerge({ a: 1, B: 2 }, { C: 3 });
    expect(result).toEqual({ a: 1, B: 2, C: 3 });
  });

  it('should be able to merge three objects', () => {
    const result = utils.deepMerge({ A: 1, B: 2 }, { C: 3 }, { D: 4 });
    expect(result).toEqual({
      A: 1,
      B: 2,
      C: 3,
      D: 4,
    });
  });

  it('should merge arrays', () => {
    const result = utils.deepMerge({ A: [1, 2] }, { A: [3, 4] });
    expect(result).toEqual({ A: [1, 2, 3, 4] });
  });

  it('should handle empty objects', () => {
    const result = utils.deepMerge({}, {});
    expect(result).toEqual({});
  });

  it('should handle null and undefined values', () => {
    const result = utils.deepMerge({ A: 1, B: null }, { B: undefined }, { c: null });
    expect(result).toEqual({ A: 1, B: undefined, c: null });
  });

  it('should handle boolean values', () => {
    const result = utils.deepMerge({ A: true, B: false }, { B: true }, { c: false });
    expect(result).toEqual({ A: true, B: true, c: false });
  });

  it('should overwrite existing properties', () => {
    const result = utils.deepMerge({ A: 1 }, { A: 2 });
    expect(result).toEqual({ A: 2 });
  });

  it('should handle circular references without infinite looping', () => {
    const obj1 = {};
    obj1.self = obj1;
    obj1.prop1 = 'value1';
    const obj2 = { prop2: 'value2' };

    expect(() => utils.deepMerge(obj1, obj2)).not.toThrow();

    expect(utils.deepMerge(obj1, obj2)).toEqual({ prop1: 'value1', prop2: 'value2' });
  });

  it('should ignore non-enumerable properties', () => {
    const result1 = utils.deepMerge({}, {});
    expect(result1).toEqual({});

    const obj1 = {};
    Object.defineProperty(obj1, 'nonEnumerableProp', {
      value: 100,
      enumerable: false,
    });
    Object.defineProperty(obj1, 'enumerableProp', {
      value: 150,
      enumerable: true,
    });
    const obj2 = {
      anotherProp: 200,
    };
    const result2 = utils.deepMerge(obj1, obj2);
    expect(result2).toEqual({ enumerableProp: 150, anotherProp: 200 });
  });

  it('should ignore prototype properties', () => {
    function Foo() {}
    Foo.prototype.foo = 'bar';
    const obj1 = new Foo();
    const obj2 = {
      anotherProp: 200,
    };
    const result = utils.deepMerge({}, obj1, obj2);
    expect(result).toEqual({ anotherProp: 200 });
  });

  it('should throw if no arguments are passed', () => {
    expect(() => utils.deepMerge()).toThrow('No objects provided for merging.');
  });

  it('should not mutate original objects', () => {
    const obj1 = { A: 1 };
    const obj2 = { B: 2 };
    const result = utils.deepMerge({}, obj1, obj2);

    expect(obj1).toEqual({ A: 1 });
    expect(obj2).toEqual({ B: 2 });
    expect(result).toEqual({ A: 1, B: 2 });
  });

  it('should handle special objects like Date, RegExp and Buffer', () => {
    const date = new Date();
    const regExp = /test/;
    const buffer = Buffer.from([1, 2, 3]);
    function MyClass() {}
    const myClass = new MyClass();

    const result = utils.deepMerge({ date, regExp }, { buffer, myClass });
    expect(result).toEqual({
      date,
      regExp,
      buffer,
      myClass,
    });

    expect(result.date instanceof Date).toBeTruthy();
    expect(result.regExp instanceof RegExp).toBeTruthy();
    expect(Buffer.isBuffer(result.buffer)).toBeTruthy();
    expect(result.myClass instanceof MyClass).toBeTruthy();
  });
});
