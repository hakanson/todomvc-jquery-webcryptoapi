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
			var defer = $.Deferred(), that = this;

			// convert password to key
			// no PBKDF2 in Chrome or IE yet, so use a salted hash
			var hmacSha256 = {name: 'hmac', hash: {name: 'sha-256'}};
			var buf = $.Uint8Util.fromString(password);

			this.authenticated = true;

			if (!this.initialized) {
				this.salt = new Uint8Array(32);
				$.WebCryptoAPI.getRandomValues(this.salt);
				this.hexSalt = $.Uint8Util.toHexString(this.salt);

				this.iv =  new Uint8Array(16);
				$.WebCryptoAPI.getRandomValues(this.iv);
				this.hexIV = $.Uint8Util.toHexString(this.iv);

				this.initialized = true;
			}

			$.WebCryptoAPI.subtle.importKey('raw', this.salt, hmacSha256, true, ['sign', 'verify']).then(function (result) {
				$.WebCryptoAPI.subtle.sign(hmacSha256, result, buf).then(function (result) {
						var keyBuf = new Uint8Array(result);

						// importKey for future AES encryption
						$.WebCryptoAPI.subtle.importKey('raw', keyBuf, {name: 'AES-CBC'}, true, ['encrypt', 'decrypt']).then(function (result) {
							that.encryptionKey = result;

							if (that.hasTodos) {
								defer.resolve(true);
							} else {
								that.setItem([]).then(function () {
									defer.resolve(true);
								}, function () {
									defer.resolve(false);
								});
							}

						}, function (e) { // TODO will these bubble up???
							window.trackJs.track(e);
							defer.resolve(false);
						});
					}, function (e) {
						window.trackJs.track(e);
						defer.resolve(false);
					});
			}, function (e) {
				window.trackJs.track(e);
				defer.resolve(false);
			});

			return defer.promise();
		},
		setItem: function (value) {
			var defer = $.Deferred(), that = this;

			var todosBuf = $.Uint8Util.fromString(JSON.stringify(value));
			var aesCbc = {name: 'AES-CBC', iv: this.iv };

			$.WebCryptoAPI.subtle.encrypt(aesCbc, this.encryptionKey, todosBuf).then(function (result) {
                var data = {
                    salt: that.hexSalt,
                    iv: that.hexIV,
                    ciphertext: $.Uint8Util.toHexString(new Uint8Array(result))
                };
				localStorage.setItem(NAMESPACE, JSON.stringify(data));
				defer.resolve();
			}, function (e) {
				window.trackJs.track(e);
				defer.reject();
			});

			return defer.promise();
		},
		getItem: function () {
			var defer = $.Deferred();
			var store = localStorage.getItem(NAMESPACE);
			var data = (store && JSON.parse(store));

			if (!data) {
				defer.resolve(null);
				return defer.promise();
			}

			if (!this.initialized) {
				this.hexSalt = data.salt;
				this.salt = $.Uint8Util.fromHexString(this.hexSalt);
				this.hexIV = data.iv;
				this.iv = $.Uint8Util.fromHexString(this.hexIV);
				this.hasTodos = !!data.ciphertext;

				this.initialized = true;
			}

			if (!this.authenticated) {
				defer.resolve(null);
				return defer.promise();
			}

			if (!data.ciphertext) {
				defer.resolve([]);

			} else {
				var todosBuf = $.Uint8Util.fromHexString(data.ciphertext);
				var aesCbc = {name: 'AES-CBC', iv: this.iv };
				$.WebCryptoAPI.subtle.decrypt(aesCbc, this.encryptionKey, todosBuf).then(function (result) {
					var plaintext = $.Uint8Util.toString(new Uint8Array(result));

					try {
						data.todos = JSON.parse(plaintext);
						defer.resolve(data.todos);
					} catch (e) {
						window.trackJs.track(e);
						defer.resolve(null);
					}

				}, function (e) {
					window.trackJs.track(e);
					defer.resolve(null);
				});
			}

			return defer.promise();
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
			var defer = $.Deferred();

			if (arguments.length > 0) {
				cryptoStorage.setItem(data).then(function () {
					defer.resolve();
				});
			} else {
				cryptoStorage.getItem().then(function (data) {
					defer.resolve(data);
				});
			}

			return defer.promise();
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

			this.validatePassword(val, confirmVal).then($.proxy(function (isValid) {
                // TODO don't use boolean, use resolve/reject functions
				if (isValid) {
					$input.val('');
				} else {
					if (confirmVal) {
						$input.val('');
					} else {
						$input.select();
					}

					$input.addClass('invalid');
				}
				this.render();
			}, this));
		},
		validatePassword: function (password, confirmPassword) {
			var result = $.Deferred(), that = this;

			if (confirmPassword && confirmPassword != password) {
				result.resolve(false);
			} else {
				cryptoStorage.authenticate(password).then(function (isAuthenticated) {
					if (isAuthenticated) {
						util.store().then(function (data) {
							that.todos = data;
							result.resolve(!!data);
						});
					} else {
						result.resolve(false);
					}
				});
			}

			return result.promise();
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
