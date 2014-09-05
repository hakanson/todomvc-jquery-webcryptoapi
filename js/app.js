/*global jQuery, Handlebars */
jQuery(function ($) {
	'use strict';

	Handlebars.registerHelper('eq', function(a, b, options) {
		return a === b ? options.fn(this) : options.inverse(this);
	});

	var ENTER_KEY = 13;
	var ESCAPE_KEY = 27;
	var NAMESPACE = 'todos-jquery-webcryptoapi';

	var cryptoStorage = {
		initialized: false,
		authenticated: false,
		salt: null,
		hexSalt: '',
		iv: null,
		hexIV: '',
		encryptionKey: null,
		hasTodos: false,
		authenticate: function (password) {
			var that = this;

			// convert password to key
			// no PBKDF2 in Chrome or IE yet, so use a salted hash
			var hmacSha256 = {name: 'hmac', hash: {name: 'sha-256'}};
			var encoder = new TextEncoder();
			var buf = encoder.encode(password);

			this.authenticated = true;

			if (!this.initialized) {
				this.salt = new Uint8Array(32);
				$.WebCryptoAPI.getRandomValues(this.salt);
				this.hexSalt = $.Uint8Util.toHexString(this.salt);

				this.iv = new Uint8Array(16);
				$.WebCryptoAPI.getRandomValues(this.iv);
				this.hexIV = $.Uint8Util.toHexString(this.iv);

				this.initialized = true;
			}

			return $.WebCryptoAPI.subtle.importKey('raw', that.salt, hmacSha256, true, ['sign', 'verify']).then(function (result) {
				return $.WebCryptoAPI.subtle.sign(hmacSha256, result, buf).then(function (result) {
					var keyBuf = new Uint8Array(result);

					// importKey for later AES encryption
					return $.WebCryptoAPI.subtle.importKey('raw', keyBuf, {name: 'AES-CBC'}, true, ['encrypt', 'decrypt']).then(function (result) {
						that.encryptionKey = result;

						if (!that.hasTodos) {
							return that.setItem([]);
						}
					});
				});
			});
		},
		setItem: function (value) {
			var encoder = new TextEncoder();
			var todosBuf = encoder.encode(JSON.stringify(value));
			var aesCbc = {name: 'AES-CBC', iv: this.iv };
			var data = {
				salt: this.hexSalt,
				iv: this.hexIV,
				ciphertext: null
			};

			return $.WebCryptoAPI.subtle.encrypt(aesCbc, this.encryptionKey, todosBuf).then(function (result) {
				data.ciphertext = $.Uint8Util.toHexString(new Uint8Array(result));
				localStorage.setItem(NAMESPACE, JSON.stringify(data));
			});
		},
		getItem: function () {
			var that = this;
			var store = localStorage.getItem(NAMESPACE);
			var data = (store && JSON.parse(store));

			var promise = new Promise(function(resolve, reject) {

				if (!data) {
					reject(new Error('no data'))
				} else {

					if (!that.initialized) {
						that.hexSalt = data.salt;
						that.salt = $.Uint8Util.fromHexString(that.hexSalt);
						that.hexIV = data.iv;
						that.iv = $.Uint8Util.fromHexString(that.hexIV);
						that.hasTodos = !!data.ciphertext;

						that.initialized = true;
					}

					if (!that.authenticated) {
						reject(new Error('not authenticated'))

					} else if (!data.ciphertext) {
						resolve([]);

					} else {
						var todosBuf = $.Uint8Util.fromHexString(data.ciphertext);
						var aesCbc = {name: 'AES-CBC', iv: that.iv };
						$.WebCryptoAPI.subtle.decrypt(aesCbc, that.encryptionKey, todosBuf).then(function (result) {
							var decoder = new TextDecoder();
							var plaintext = decoder.decode(new Uint8Array(result));

							try {
								data.todos = JSON.parse(plaintext);
								resolve(data.todos);
							} catch (err) {
								window.trackJs.track(err);
								reject(err);
							}

						}, function (err) {
							window.trackJs.track(err);
							reject(err);
						});
					}
				}
			});

			return promise;
		}
	};

	var util = {
		uuid: function () {
			/*jshint bitwise:false */
			var i, random;
			var uuid = '';

			for (i = 0; i < 32; i++) {
				random = Math.random() * 16 | 0;
				if (i === 8 || i === 12 || i === 16 || i === 20) {
					uuid += '-';
				}
				uuid += (i === 12 ? 4 : (i === 16 ? (random & 3 | 8) : random)).toString(16);
			}

			return uuid;
		},
		pluralize: function (count, word) {
			return count === 1 ? word : word + 's';
		},
		store: function (data) {
			if (data) {
				return cryptoStorage.setItem(data);
			} else {
				return cryptoStorage.getItem();
			}
		}
	};

	var App = {
		init: function () {
			this.todos = null;
			util.store().then($.proxy(function (data) {
				this.todos = data;
			}, this));
			this.cacheElements();
			this.bindEvents();

			Router({
				'/:filter': function (filter) {
					this.filter = filter;
					this.render();
				}.bind(this)
			}).init('/all');
		},
		cacheElements: function () {
			this.todoTemplate = Handlebars.compile($('#todo-template').html());
			this.footerTemplate = Handlebars.compile($('#footer-template').html());
			this.$todoApp = $('#todoapp');
			this.$header = this.$todoApp.find('#header');
			this.$main = this.$todoApp.find('#main');
			this.$footer = this.$todoApp.find('#footer');
			this.$newTodo = this.$header.find('#new-todo');
			this.$toggleAll = this.$main.find('#toggle-all');
			this.$todoList = this.$main.find('#todo-list');
			this.$count = this.$footer.find('#todo-count');
			this.$clearBtn = this.$footer.find('#clear-completed');

			this.$password = $('#todo-password');
		},
		bindEvents: function () {
			var list = this.$todoList;
			this.$newTodo.on('keyup', this.create.bind(this));
			this.$toggleAll.on('change', this.toggleAll.bind(this));
			this.$footer.on('click', '#clear-completed', this.destroyCompleted.bind(this));
			list.on('change', '.toggle', this.toggle.bind(this));
			list.on('dblclick', 'label', this.edit.bind(this));
			list.on('keyup', '.edit', this.editKeyup.bind(this));
			list.on('focusout', '.edit', this.update.bind(this));
			list.on('click', '.destroy', this.destroy.bind(this));

			this.$password.on('keyup', this.processPassword.bind(this));
		},
		render: function () {
			var todos, placeholder;

			if (this.todos) {
				this.$password.addClass('hidden');

				todos = this.getFilteredTodos();
				this.$todoList.html(this.todoTemplate(todos));
				this.$main.toggle(todos.length > 0);
				this.$toggleAll.prop('checked', this.getActiveTodos().length === 0);
				this.renderFooter();
				this.$newTodo.removeClass('hidden').focus();
				util.store(this.todos);

			} else {
				if (!cryptoStorage.initialized) {
					placeholder = (this.$password.data('confirm') ? 'Confirm Password' : 'Set Password');
					this.$password.attr('placeholder', placeholder);
				}
				this.$password.removeClass('hidden').focus();
			}
		},
		renderFooter: function () {
			var todoCount = this.todos.length;
			var activeTodoCount = this.getActiveTodos().length;
			var template = this.footerTemplate({
				activeTodoCount: activeTodoCount,
				activeTodoWord: util.pluralize(activeTodoCount, 'item'),
				completedTodos: todoCount - activeTodoCount,
				filter: this.filter
			});

			this.$footer.toggle(todoCount > 0).html(template);
		},
		processPassword: function (e) {
			var that = this;
			var $input = $(e.target);
			var val = $input.val().trim();

			$input.removeClass('invalid');

			if (e.which !== ENTER_KEY || !val) {
				return;
			}

			var confirmVal = $input.data('confirm');
			$input.data('confirm', null);
			if (!cryptoStorage.initialized) {
				if (!confirmVal) {
					$input.data('confirm', val);
					$input.val('');
					this.render();
					return;
				}
			}

			this.validatePassword(val, confirmVal).then(function () {
				$input.val('');
			}).catch(function () {
				if (confirmVal) {
					$input.val('');
				} else {
					$input.select();
				}
				$input.addClass('invalid');
			}).then(function () {
				that.render();
			});
		},
		validatePassword: function (password, confirmPassword) {
			var that = this;

			if (confirmPassword && confirmPassword != password) {
				return new Promise(function(resolve, reject) {
					reject(new Error('passwords do not match'));
				});
			}
			return cryptoStorage.authenticate(password).then(function () {
				return util.store();

			}).then(function (result) {
				that.todos = result;

			})
		},
		toggleAll: function (e) {
			var isChecked = $(e.target).prop('checked');

			this.todos.forEach(function (todo) {
				todo.completed = isChecked;
			});

			this.render();
		},
		getActiveTodos: function () {
			return this.todos.filter(function (todo) {
				return !todo.completed;
			});
		},
		getCompletedTodos: function () {
			return this.todos.filter(function (todo) {
				return todo.completed;
			});
		},
		getFilteredTodos: function () {
			if (this.filter === 'active') {
				return this.getActiveTodos();
			}

			if (this.filter === 'completed') {
				return this.getCompletedTodos();
			}

			return this.todos;
		},
		destroyCompleted: function () {
			this.todos = this.getActiveTodos();
			this.filter = 'all';
			this.render();
		},
		// accepts an element from inside the `.item` div and
		// returns the corresponding index in the `todos` array
		indexFromEl: function (el) {
			var id = $(el).closest('li').data('id');
			var todos = this.todos;
			var i = todos.length;

			while (i--) {
				if (todos[i].id === id) {
					return i;
				}
			}
		},
		create: function (e) {
			var $input = $(e.target);
			var val = $input.val().trim();

			if (e.which !== ENTER_KEY || !val) {
				return;
			}

			this.todos.push({
				id: util.uuid(),
				title: val,
				completed: false
			});

			$input.val('');

			this.render();
		},
		toggle: function (e) {
			var i = this.indexFromEl(e.target);
			this.todos[i].completed = !this.todos[i].completed;
			this.render();
		},
		edit: function (e) {
			var $input = $(e.target).closest('li').addClass('editing').find('.edit');
			$input.val($input.val()).focus();
		},
		editKeyup: function (e) {
			if (e.which === ENTER_KEY) {
				e.target.blur();
			}

			if (e.which === ESCAPE_KEY) {
				$(e.target).data('abort', true).blur();
			}
		},
		update: function (e) {
			var el = e.target;
			var $el = $(el);
			var val = $el.val().trim();

			if ($el.data('abort')) {
				$el.data('abort', false);
				this.render();
				return;
			}

			var i = this.indexFromEl(el);

			if (val) {
				this.todos[i].title = val;
			} else {
				this.todos.splice(i, 1);
			}

			this.render();
		},
		destroy: function (e) {
			this.todos.splice(this.indexFromEl(e.target), 1);
			this.render();
		}
	};

	App.init();
});
