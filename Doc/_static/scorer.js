// Search scorer: the defaults of Sphinx, plus a boost for the guides,
// so that a search for a task ("encrypt", "sign", "password", ...)
// shows the guide before the many API methods with the same name.
var Scorer = {
  score: (result) => {
    const [docname, title, anchor, descr, score, filename, kind] = result;
    return docname.startsWith("src/guides/") ? score + 8 : score;
  },

  // query matches the full name of an object
  objNameMatch: 11,
  // or matches in the last dotted part of the object name
  objPartialMatch: 6,
  // Additive scores depending on the priority of the object
  objPrio: {
    0: 15, // used to be importantResults
    1: 5, // used to be objectResults
    2: -5, // used to be unimportantResults
  },
  //  Used when the priority is not in the mapping.
  objPrioDefault: 0,

  // query found in title
  title: 15,
  partialTitle: 7,
  // query found in terms
  term: 5,
  partialTerm: 2,
};
